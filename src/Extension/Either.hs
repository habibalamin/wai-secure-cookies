module Extension.Either (rightToMaybe) where

rightToMaybe :: Either e a -> Maybe a
rightToMaybe (Left _) = Nothing
rightToMaybe (Right a) = Just a
