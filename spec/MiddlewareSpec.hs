{-# LANGUAGE OverloadedStrings #-}

module MiddlewareSpec where

import Test.Hspec
import Test.Hspec.Wai
import Test.Hspec.Wai.Internal (withApplication)
import System.Environment
import Cookie.Secure.Middleware
import Network.Wai
import Network.Wai.Test hiding (request)
import Network.HTTP.Types
import Network.HTTP.Types.Status
import Network.HTTP.Types.Header
import Data.Foldable
import Data.Maybe
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as LB

spec :: Spec
spec = do
  before_ setupEnvironment $ do
    describe "secureCookies middleware" $ do
      it "does not encrypt cookie names" $ do
        cookie <- getResponseCookie
        cookie `shouldStartWith` "SessionId="

      it "encrypts cookie values" $ do
        cookie <- getResponseCookie
        cookie `shouldNotContain` sessionId

      it "does not decrypt cookie names" $ do
        cookie <- getRequestCookie
        cookie `shouldStartWith` "SessionId="

      it "decrypts cookie values" $ do
        cookie <- getRequestCookie
        cookie `shouldEndWith` sessionId

setupEnvironment :: IO ()
setupEnvironment =
     setEnv "WAI_COOKIE_ENCRYPTION_KEY" "00000000000000000000000000000000"
  >> setEnv "WAI_COOKIE_VALIDATION_KEY" "00000000000000000000000000000000"

getResponseCookie :: IO String
getResponseCookie =
  withApplication secureApp
    $ getHeaderValue hSetCookie . simpleHeaders <$> get "/"

getRequestCookie :: IO String
getRequestCookie =
  withApplication secureApp
    $   LB.unpack . simpleBody
    <$> request
          methodGet
          "/"
          [ ( hCookie
            , B.pack exampleSignedEncryptedCookieValue
            )
          ]
          ""

exampleSignedEncryptedCookieValue :: String
exampleSignedEncryptedCookieValue = "SessionId=aXYsUWxmbDhWLW90alJDTGtHSUh2Uno5Z3xPSkhTYjZsOTFsVnA|signature.be2ee0eb3d894ef671a8475d78c635d28e844011eda7ae16c47830333466d1e0"

getHeaderValue :: HeaderName -> [Header] -> String
getHeaderValue header =
  B.unpack
    . snd
    . fromMaybe ("", "")
    . findHeader header
    where
      findHeader header = find $ (== header) . fst

secureApp :: Application
secureApp = secureCookies app

app :: Application
app request responder = responder
  $ responseLBS
      status200
      [ ( hSetCookie
        , B.pack $ "SessionId=" ++ sessionId ++ "; Max-Age=86400"
        )
      ]
      (LB.pack . getHeaderValue hCookie $ requestHeaders request)

sessionId :: String
sessionId = "123456789"
