module Extension.ByteString (stripPrefix, stripSuffix) where

import Data.ByteString (ByteString(..))
import qualified Data.ByteString.Char8 as BS
import Data.Maybe (fromMaybe)

stripPrefix :: ByteString -> ByteString -> ByteString
stripPrefix prefix = maybeOriginal $ BS.stripPrefix prefix

stripSuffix :: ByteString -> ByteString -> ByteString
stripSuffix suffix = maybeOriginal $ BS.stripSuffix suffix

maybeOriginal :: (a -> Maybe a) -> a -> a
maybeOriginal f g = fromMaybe g $ f g
