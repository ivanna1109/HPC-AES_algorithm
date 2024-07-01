#!/bin/bash
# set the number of nodes and processes per node

#SBATCH --nodes=1

# set the number of tasks (processes) per node.
#SBATCH --ntasks-per-node=1

#SBATCH --partition=all
# set max wallclock time
#SBATCH --time=15:00:00

# set name of job
#SBATCH --job-name=seqAES


./aesSeq