{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
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

import Crypto.PubKey.RSA.Types (PrivateKey)
import qualified Crypto.Store.PKCS8 as PKCS8
import qualified Crypto.Store.X509 as X509
import Data.Foldable (toList)
import Data.Text (Text)
import qualified Data.Text.Encoding as T
import qualified Data.X509 as X509
import Network.Wai.Parse
import Network.Wai.SAML2 as SAML2
import Network.Wai.SAML2.Validation (validateResponse)
import UnliftIO (throwIO)
import Yesod.Auth
import Yesod.Core
import Yesod.Core.Types hiding (Logger)

-- | Metadata shared between IdP and SP
type RelayState = Text

-- | A function to fetch 'SAML2Config' dynamically
type FetchConfig master = Maybe RelayState -> AuthHandler master SAML2Config

type Logger master = Maybe RelayState -> Either SAML2Error Assertion -> AuthHandler master ()

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

plugin :: forall master. YesodAuth master
    => Logger master
    -> FetchConfig master
    -> AuthPlugin master
plugin logger fetchConfig = AuthPlugin pluginName dispatch login where
    dispatch :: Text -> [Text] -> AuthHandler master TypedContent
    dispatch "POST" ["login"] = authLogin logger fetchConfig
    dispatch _ _ = notFound
    login _ = [whamlet||] -- TODO

authLogin
    :: Logger master
    -> FetchConfig master
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
  cfg <- fetchConfig relayState

  assertion <- case lookup "SAMLResponse" body of
    Just val ->
      liftIO (validateResponse cfg val) >>= \case
        Left err -> do
          logger relayState (Left err)
          throwIO $ HCError NotAuthenticated
        Right a -> a <$ logger relayState (Right a)
    Nothing -> throwIO $ HCError $ InvalidArgs ["SAMLResponse is missing"]

  let extra = ((,) "RelayState" <$> toList relayState)
          ++ [ (k, v)
          | AssertionAttribute {attributeName = k, attributeValue = v}
            <- assertionAttributeStatement assertion
          ]

  let Subject {subjectNameID} = assertionSubject assertion
  setCredsRedirect (Creds pluginName (nameIDValue subjectNameID) extra) >>= sendResponse
