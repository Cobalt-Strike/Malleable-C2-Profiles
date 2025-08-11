# Malleable C2 Profiles

A Malleable C2 profile is a simple program that modifies the behavior of the Cobalt Strike Beacon. 

[This repository](https://github.com/Cobalt-Strike/Malleable-C2-Profiles) contains a set of Malleable C2 profiles aimed to help with the creation of your own. The best way to create a profile is to modify an existing one. Several example profiles are available in this repository.

<center><img width="20%" height="20%" alt="disguised_cs_guy" src="https://github.com/user-attachments/assets/1e858fed-783a-4265-9e02-719e4a09d169" /></center>

You can find a reference profile with all the possible options available [here](https://github.com/Cobalt-Strike/Malleable-C2-Profiles/blob/master/normal/reference.profile).

### Tips & Tricks

It is recommended to avoid defaults in the Cobalt Strike profile to improve evasiveness and mimic threats. You can modify things like:

- Avoiding using ```rwx```
- How the process injection behavior works (which APIs will be used) in the ```process-inject``` section
- How the ```fork and run``` works in the ```post-ex``` section
- The default sleep time for beacons
- The max size of binaries to be loaded in memory
- The memory footprint and DLL content with ```stage``` section
- The network traffic

## Contribute

If you'd like to contribute.

- Submit a pull request
- Keep content organized

## References

- [Community Kit](https://cobalt-strike.github.io/community_kit/)
- [Malleable C2](https://www.cobaltstrike.com/product/features/malleable-c2)
