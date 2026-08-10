## Some Fun Results and Graphs 

Please note that some the images below are not from the scame scripts as provided; however, the provided scripts should provide a similar result.

### Xeon DDP Gap
During our testing the Intel's XEON GOLD 5512U (contains a slightly newer core compared to the i9), we found that the DDP with Xeon refuses to fetch




### Shorter Training Length
In section 5 of the paper, the stated minimum needed training is ~300. However, we found that if the `train_aop` is flushed from the L1 cache, and thus the stram exposed to the DDP again, the training length can be reduced by 30 times. This makes the DDP more aggressive than previously thought. Below is an image showing the difference between flushing and no flushing on both i9 and Xeon.

### Some Fun Graphs helping vislize the DMP access pattern 



