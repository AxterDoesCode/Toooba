Content directed prefetcher plan:
I want you to further develop the content-directed prefetcher located in CDP.bsv, currently there is a module mkCDPStatefulRelative which is what I've been working on.
The core idea is to scan incoming cache lines for potential virtual addresses, and see if we can learn anything about offsets in the access patterns to guide prefetch.
Currently this prefetcher I've designed doesn't perform very well, I would like for you to continuously iterate and improve on the general CDP idea.
Some key files are:
CDP.bsv
L1Bank.bsv
everything in the prefetcher directory

Test everything end-to-end, make it perfect, you can use agents, I'm on a 20x max plan. Create skills when you make progress on CDP understanding
You can run CPU benchmarks by going to ./builds/RV64ACDFIMSU_Toooba_bluesim and running "make clean compile simulator benchmarks".
Understand how the benchmark scripts work as well.
The CPU benchmarks emit logs, in ./TooobaLogParser we can parse the logs and gain useful insights into how the prefetcher performs with various changes.
Feel free to improve the TooobaLogParser to gain more useful insights. Also it would be good to inspect the Logs directly to learn about behaviour of the prefetcher.
Some of the CPU benchmarks take a while to run, if you want to speed up iteration time, disable more of the benchmarks in the python script, some that I specically want to keep is treeadd, health, em3d, voronoi and patricia.

Currently the prefetcher only shows promising results in the patricia CPU benchmark, this work would hopefully make the prefetcher better across other pointer chasing benchmarks.
Some useful research papers you can look at are:
- Path confidence based lookahead prefetching
- A stateless, content-directed data prefetching mechanism (the original CDP paper which doesn't perform very well)
- Techniques for Bandwidth-Efficient Prefetching of Linked Data Structures in Hybrid Prefetching Systems
- Improved Prefetching Techniques for Linked Data Structures

Additionally in ThingsToTry.txt I've been writing about various thoughts and things I've implemented/wanted to implement.
Have a look there too if there's anything interesting.
Feel free to create new varitions of CDP prefetchers as well if the underlying technique changes vastly, so that we can make comparisons.
Also, there is limited disk space on the home directory, you can use storage in /local/scratch/ac2822/NewTooobaLogs if you want to store Log files somewhere else since they get overwritten when you rerun benchmarks
You can change the prefetcher used in Prefetcher_top.bsv by editing ./builds/Resources/Include_RISCY_Config.mk

Finally, keep everything in the ac2822CDPDeepDive branch, create new branches if needed, don't touch the master branch.
