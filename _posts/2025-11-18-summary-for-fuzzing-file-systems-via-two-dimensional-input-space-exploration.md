---
title: "Summary for "Fuzzing File Systems via Two-Dimensional Input Space Exploration""
date: 2025-11-18 01:28:16 +0900
categories: [Papers]
tags: []
---

# Summary for "Fuzzing File Systems via Two-Dimensional Input Space Exploration"

# Index
- [1. Introduction](#Introduction)
    - [1.1 Contribution](#contributions)
    - [1.2 Threat Model](#threat-model)
- [2. Background and motivation](#background-and-motivation)

# Introduction
File system: Basic system services of an OS, manage files, tolerate system crashes without losing data consistency <br>

Bugs in file system -> Can cause devastating errors + security threats (mounting crafted disk image, invoke vulnerable operations..) <br>

ext4, XFS, Btrfs, F2FS -> conventional file systems run in the OS kernel <br>

But, file system implementation is very large and still under active development -> Hard to manually eliminate every bug<br>

Most file systems -> Rely on the known stres-testing frame-works(xfstests, fsck, Linux Test Project...) <br>

These mostly focus on the regression of file systems with minimal integrity checks <br>

In addition, some prior works have applied model checking => Requires deep understanding of file system and OS states -> Little impractical <br>

Fuzzing file systems is dependent on two inputs: Mounted disk image, Sequence of file operations(ex: syscall) that are executed on mounted image <br>

Existing fuzzers either focus on... <br>
1. Mutating images as ordinary binary inputs 
2. Generating random sets of file operation-specific syscalls

Failed because of following three challenges... <br>

1. Disk image is a large binary blob that is structured but complicated -> Heavy I/O involved in mutating images. Existing fuzzers mutate only non-zero chunks in an image -> Unsound + Existing fuzzers fail to fix any metadata checksum after corrupting data blocks
2. File-operations are context-aware workloads(ex: Dependence exists between an image and file operations on it) Existing system call fuzzers (independently generate random system calls with hard-coded file paths) 
-> fail to emit meaningful sequences of file operations 
3. Most of OS, file system fuzzers test generated input without reloading fresh copy of the OS(due to performance issue) -> Leading to dirty OS state 

**JANUS**: Feedback-driven fuzzer, effectively explores **two-dimensional** input space of a disk file system <br>

1. Exploit structued data property in the form of metadata -> Pruning searching space of the input
2. Propose **image-directed syscall fuzzing** to fuzz file operations (ex: Not only stores generated system calls but also deduce runtime status of every file object after syscall completion) -> Then uses speculated status as feedback to generate a new system calls, thereby emitting context-aware workloads. 
During each fuzzing iteration, JANUS performs image fuzzing with higher priority and invoke image-directed syscall fuzzing 
3. Solve reproducibility by always loading fresh copy of OS(with the help of a library OS, ex: LKL) running in user space

## Contributions
Identify three prominent issues 
1. Fuzzing a large blob image is inefficient
2. Existing fuzzers do not exploit the dependence between a file system image and file operations
3. Aging OS and file system

Approach: Efficiently mutates metadata block in a large seed image while generating image-directed workloads + Leverage library OS <br>

## Threat Model
Attacker is privileged to mount a fully crafted disk image on a target machine and operate files stored on the image to exploit security-bugs <br>

Attackers can achieve this without root privilege with...
1. Auto-mounting, Modern OS automatically mount an untrusted plugged-in drive if it supports corresponding file system
2. Unprivileged mounts: allowing unprivileged users to mount disk image, file system 

# BACKGROUND and MOTIVATION
Commodity OS -> Usually implement a disk file system as a kernel module <br>

User: tasked with mounting the **large-size** and **formatted** image and manage data via file operations <br>

In this section..
1. Describe general fuzzing approaches and existing file system fuzzers
2. Explain why they all fail to efficiently test file system 
3. Summarize challenges and potential opportunities in file system fuzzing

## A. A Primer on Fuzzing
Fuzzing: Popular softwware-testing method by repeatedly generating new input and injecting them into target program <br>

Recent fuzzers leverage the past code coverage to later direct the input generation <br>

## B. File System Fuzzing
Disk file system has two-dimensional input space: <br>
1. Structured file system image format
2. File operations that users invoke to access file stored on a mounted image 

### Disk Image Fuzzer
Disk image: large structured binary blob <br>

Blob has
1. User data
2. Metadata that a file system needs to access, load, recover, and search data or tu fullfill other specific requirements 

![ext4](/assets/img/posts/papers/JANUS_1.png) <br>
Above presents on-disk layout of typical ext4 image. However the size of metadata constitutes really small part of image size <br>

This means => Minimum size of a valid image is large for fuzzing input <br>

Issues that occur when using an image as a fuzzing input: <br>

1. Exponential increase in the input space exploration
2. Frequent read, write, mutation... => Slowing down file operation + Huge overhead 
3. Mutated metablock without correct checksum => Rejected by kernel during initialization

Disk image fuzzers enforce a file system to mount, execute sequence of file operations on mutated disk images <br>

Early Fuzzers: Mutate bytes at random offset, or bytes in metadata blocks => Heavy I/O, Poor performance <br>

Recent Fuzzers: Driven by code coverage. Extract all the non-zero chunks in a seed image for mutation => Results in sub-optimal file system fuzzing + Fail to fix checksum <br>

### File Operation Fuzzer
File system => Part of OS. <br>

General approach: Invoke a set of system calls (syzkaller, trinity, triforceAFL..) -> Porting these fuzzers to target file system is straightforward, but fail (efficiency) <br>

#### Modify only file objects
File operation modify only file objects (directories, symbolic links...) that exist on the image, and complete operation affects particular objects. 
Existing OS fuzzers do not consider dynamic dependence between image and file operations. <br>
**Blindly** generate system calls => Explore file system superficially<br>

#### Mostly use virtualized instance
Existing OS fuzzers mostly use virtualized instance(KVM, QEMU..) without reloading fresh OS. This leads to two issues: <br>
Non-deterministic after numerous system calls (ex: kmalloc depends on prior allocation, behaves differently across runs)

### File System Fuzzer
To fuzz the OS -> Most fuzzer either fuzz a **binary input** or use a **sequence of system calls** <br>

To fuzz file system, need to mutate two inputs:
1. Binary image(ex: file system image)
2. Corresponding workload(ex: set of file system specific system calls) 

But combining these is not straightforward..

## C. Challenges of Fuzzing a File System
Set of challenges of fuzzing file system in linux kernel <br>

### Handling large disk images as input
To efficiently fuzz complicated, large disk image:
1. Mutate scattered metadata in the image with checksum 
2. Mitigate frequent disk I/O due to input manipulation 

Current fuzzers fails to address above issues simultaneously <br>

Ideal image fuzzer -> Should target only the metadata + Fix checksum for mutated metadata structure

### Missing context-aware workloads
File system-aware workloads => Directly affect the image <br>

For example... <br>

Valid file operation: Modify file objects on an image (ex: open() creates a new file and link, unlink() removes one link) <br>

Existing fuzzer: Rely on predefined image information to generate system calls => Fail to comprehensively test all the accessible file objects in a target file system at runtime <br>

Better Approach: Maintain runtime status of every file object on an image after performing past file operations for generating new ones 

### Exploring input space in two dimensions
File system -> Processes two types of inputs: <br>

Disk images and file operations -> Organized in completely different formats (ex: binary blob v.s. Sequential operations) but have implicit connection between them <br>

To explore fully explore file system => Have to mutate both of them(not supported by existing fuzzers)

# DESIGN
JANUS: feedback-driven fuzzer that mutates metadata of a seed image, while generating context-aware file operations <br>

