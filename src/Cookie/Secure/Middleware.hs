{-# LANGUAGE OverloadedStrings #-}

module Cookie.Secure.Middleware (secureCookies) where

import Network.Wai (Middleware
                  , Request
                  , ResponseReceived
                  , responseLBS
                  , requestHeaders
                  , responseHeaders)
import Network.Wai.Internal (Response(..))
import Network.HTTP.Types.Header (Header
                                , RequestHeaders
                                , ResponseHeaders)
import Network.HTTP.Types.Status (status200)
import qualified Data.ByteString.Char8 as BS
import Data.Maybe (catMaybes)
import Cookie.Secure (encryptAndSignIO, verifyAndDecryptIO)
import Data.List.Split (splitOn)

secureCookies :: Middleware
secureCookies app request respondWith =
  verifyAndDecryptCookies request
  >>= flip app (encryptAndSignCookies respondWith)

verifyAndDecryptCookies :: Request -> IO Request
verifyAndDecryptCookies request =
  replaceRequestHeaders request
  <$> mapM verifyAndDecryptIfCookieHeader (requestHeaders request)

encryptAndSignCookies
  :: (Response -> IO ResponseReceived)
  -> Response -> IO ResponseReceived
encryptAndSignCookies respondWith response = do
  mapM encryptAndSignIfSetCookieHeader (responseHeaders response)
  >>= respondWith . replaceResponseHeaders response

encryptAndSignIfSetCookieHeader :: Header -> IO Header
encryptAndSignIfSetCookieHeader header =
  if fst header == "Set-Cookie"
  then encryptAndSignCookieHeader header
  else return header

encryptAndSignCookieHeader :: Header -> IO Header
encryptAndSignCookieHeader (name, value) = (,)
  <$> return name
  <*> encryptedSignedCookieHeaderValue
    where
      (cookie, metadata) = BS.break (== ';') value
      encryptedSignedCookieHeaderValue =
        flip BS.append metadata <$> encryptAndSignCookie cookie
      encryptAndSignCookie c = do
        let cookieNameValueList = map BS.pack . splitOn "=" $ BS.unpack c
        let cName = head cookieNameValueList
        let cValue = last cookieNameValueList

        encryptedValue <- encryptAndSignIO cValue

        return $ BS.intercalate "=" [cName, encryptedValue]

replaceRequestHeaders :: Request -> RequestHeaders -> Request
replaceRequestHeaders request newHeaders =
  request { requestHeaders = newHeaders }

-- OPTIMIZE: Response is imported from Network.Wai.Internal, which
-- interface is not guaranteed to be stable.
replaceResponseHeaders :: Response -> ResponseHeaders -> Response
replaceResponseHeaders
  (ResponseFile status headers filepath possibleFilepart) newHeaders =
    ResponseFile status newHeaders filepath possibleFilepart
replaceResponseHeaders (ResponseBuilder status headers builder) newHeaders =
  ResponseBuilder status newHeaders builder
replaceResponseHeaders (ResponseStream status headers body) newHeaders =
  ResponseStream status newHeaders body
replaceResponseHeaders (ResponseRaw toStreaming response) newHeaders =
  ResponseRaw toStreaming (replaceResponseHeaders response newHeaders)

verifyAndDecryptIfCookieHeader :: Header -> IO Header
verifyAndDecryptIfCookieHeader header =
  if fst header == "Cookie"
  then verifyAndDecryptCookieHeader header
  else return header

verifyAndDecryptCookieHeader :: Header -> IO Header
verifyAndDecryptCookieHeader (name, value) = (,)
  <$> return name
  <*> verifyAndDecryptCookieHeaderValue value
    where
      verifyAndDecryptCookieHeaderValue value =
        BS.intercalate "; "
        <$> mapM verifyAndDecryptCookie
        (splitOn "; " (BS.unpack value))
      verifyAndDecryptCookie cookie =
        -- OPTIMIZE: maybe silently dropping cookies which fail to verify
        -- or decrypt isn't the best idea?
        BS.intercalate "=" . catMaybes
        <$> mapM verifyAndDecryptIO
        (map BS.pack (splitOn "=" cookie))
