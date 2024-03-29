{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Yesod.Auth.SAML2
  ( SAML2Config,
    FetchConfig,
    RelayState,
    plugin,
    -- Utilities
    PrivateKey,
    parsePKCS8,
    fromX509,
    Logger,
  )
where

import Control.Monad.Trans.Except
import Crypto.PubKey.RSA.Types (PrivateKey)
import qualified Crypto.Store.PKCS8 as PKCS8
import qualified Crypto.Store.X509 as X509
import Data.Foldable (toList)
import Data.Text (Text)
import qualified Data.Text.Encoding as T
import Data.Time.Clock (getCurrentTime)
import qualified Data.X509 as X509
import Network.Wai.Parse
import Network.Wai.SAML2 as SAML2
import Network.Wai.SAML2.Response
import Network.Wai.SAML2.Validation
import UnliftIO (throwIO)
import Yesod.Auth
import Yesod.Core
import Yesod.Core.Types hiding (Logger)

-- | Metadata shared between IdP and SP
type RelayState = Text

-- | A function to fetch 'SAML2Config' dynamically
type FetchConfig context master = Response -> Maybe RelayState -> AuthHandler master (context, SAML2Config)

type Logger context master = Maybe context -> Maybe RelayState -> Maybe Response -> Either SAML2Error Assertion -> AuthHandler master ()

-- | Decode a private key encoded in PEM / PKCS8 format
parsePKCS8 :: Text -> Either String PrivateKey
parsePKCS8 pem = case PKCS8.readKeyFileFromMemory $ T.encodeUtf8 pem of
  [PKCS8.Unprotected (X509.PrivKeyRSA key)] -> pure key
  [PKCS8.Unprotected other] -> Left $ "Expected PrivKeyRSA, but got " <> show other
  [PKCS8.Protected _] -> Left "expected an unprotected key"
  other -> Left $ "expected a single key; got " <> show (length other)

-- | Create 'SAML2Config' from a private key and an X.509 certificate
fromX509 :: PrivateKey -> Text -> Either String SAML2Config
fromX509 saml2PrivKey certificate = do
  saml2PubKey <-
    case X509.readSignedObjectFromMemory $ T.encodeUtf8 certificate of
      [signedCert] -> case X509.certPubKey $ X509.signedObject $ X509.getSigned signedCert of
        X509.PubKeyRSA key -> pure key
        other -> Left $ "Expected PubKeyRSA, but got " <> show other
      _ -> Left "Failed to parse certificate"

  pure (SAML2.saml2Config saml2PrivKey saml2PubKey)

pluginName :: Text
pluginName = "saml2"

plugin :: forall context master. YesodAuth master
    => Logger context master
    -> FetchConfig context master
    -> AuthPlugin master
plugin logger fetchConfig = AuthPlugin pluginName dispatch login where
    dispatch :: Text -> [Text] -> AuthHandler master TypedContent
    dispatch "POST" ["login"] = authLogin @context logger fetchConfig
    dispatch _ _ = notFound
    login _ = [whamlet||] -- TODO

authLogin
    :: Logger context master
    -> FetchConfig context master
    -> AuthHandler master TypedContent
authLogin logger fetchConfig = do

  -- Obtain the request body
  req <- waiRequest
  let bodyOpts =
        setMaxRequestNumFiles 0 $
          setMaxRequestFileSize 0 $
            defaultParseRequestBodyOptions
  (body, _) <- liftIO $ parseRequestBodyEx bodyOpts lbsBackEnd req

  let relayState = T.decodeUtf8 <$> lookup "RelayState" body

  assertion <- case lookup "SAMLResponse" body of
    Just responseData -> do
      now <- liftIO getCurrentTime
      (responseXmlDoc, samlResponse) <- liftIO (runExceptT (decodeResponse responseData)) >>= \case
        Left err -> do
          logger Nothing relayState Nothing (Left err)
          throwIO $ HCError $ InvalidArgs ["SAMLResponse"]
        Right a -> pure a

      (context, cfg) <- fetchConfig samlResponse relayState

      liftIO (runExceptT (validateSAMLResponse cfg responseXmlDoc samlResponse now)) >>= \case
        Left err -> do
          logger (Just context) relayState (Just samlResponse) (Left err)
          throwIO $ HCError NotAuthenticated
        Right a -> a <$ logger (Just context) relayState (Just samlResponse) (Right a)
    Nothing -> throwIO $ HCError $ InvalidArgs ["SAMLResponse is missing"]

  let extra = ((,) "RelayState" <$> toList relayState)
          ++ [ (k, v)
          | AssertionAttribute {attributeName = k, attributeValue = v}
            <- assertionAttributeStatement assertion
          ]

  let Subject {subjectNameID} = assertionSubject assertion
  setCredsRedirect (Creds pluginName (nameIDValue subjectNameID) extra) >>= sendResponse
