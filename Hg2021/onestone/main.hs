import Control.Monad
import Data.IORef
import qualified Options.Applicative as O
import qualified Data.Vector.Unboxed.Mutable as V

argsParser :: O.Parser (Int, Int)
argsParser = (,)
    <$> O.argument O.auto (mconcat
            [ O.help "Index to write value to"
            , O.metavar "INDEX"
            ])
    <*> O.argument O.auto (mconcat
            [ O.help "Value to write"
            , O.metavar "VALUE"
            ])

main :: IO ()
main = do
    (index, value) <- O.execParser $ O.info (argsParser O.<**> O.helper) mempty
    vector <- V.replicate 100 0
    V.unsafeWrite vector index value
    countRef <- newIORef (0 :: Int)
    V.forM_ vector $ \i -> when (i /= 0) $ modifyIORef countRef (+1)
    count <- readIORef countRef
    putStrLn $ "count: " <> show count
    when (count > 1) $ do
        flag <- readFile "flag.txt"
        putStr flag
