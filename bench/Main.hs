-- You can benchmark your code quickly and effectively with Criterion. See its
-- website for help: <http://www.serpentine.com/criterion/>.
import Criterion.Main

import Control.Monad
import Control.DeepSeq
import Control.Exception

import qualified Crypto.Lithium.Box as Box
import BoxBench
import HashBench
import RandomBench
import SignBench

main :: IO ()
main = do
  boxToEval <- boxEnv
  boxKeys <- evaluate $ force boxToEval

  signToEval <- signEnv
  signKey <- evaluate $ force signToEval

  defaultMain $
    [ benchBox boxKeys
    , benchHash
    , benchSign signKey
    ]
