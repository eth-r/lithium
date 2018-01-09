-- You can benchmark your code quickly and effectively with Criterion. See its
-- website for help: <http://www.serpentine.com/criterion/>.
import Criterion.Main

import BoxBench
import HashBench
import RandomBench

main :: IO ()
main = benchBox
-- main = defaultMain [ benchBox
--                    -- , benchRandom
--                    -- , benchHash
--                    ]
