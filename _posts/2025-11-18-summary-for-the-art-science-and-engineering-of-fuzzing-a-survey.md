---
title: "Summary for The Art, Science, and Engineering of Fuzzing: A Survey"
date: 2025-11-18 01:28:16 +0900
categories: [Papers]
tags: []
---

# Summary for The Art, Science, and Engineering of Fuzzing: A Survey

## Index
- [1. Introduction](#introduction)
- [2. Systemization, Taxonomy, And Test Programs](#systemization-taxonomy-and-test-programs) 
	- [2.1 Fuzzing & Fuzz Testing](#fuzzing--fuzz-testing) 
	- [2.3 Fuzz Testing Algorithm](#fuzz-testing-algorithm) 
	- [2.4 Taxonomy of Fuzzers](#taxonomy-of-fuzzers)
- [3. Preprocess](#preprocess)
	- [3.1 Instrumentation](#instrumentation)
	- [3.2 Seed Selection](#seed-selection)
	- [3.3 Seed Trimming](#seed-trimming)
	- [3.4 Preparing a Driver Application](#preparing-a-driver-application)
- [4. Scheduling](#scheduling)
	- [4.1 The Fuzz Configuration Scheduling (FCS) Problem](#the-fuzz-configuration-schedulingfcs-problem)
	- [4.2 Black-box FCS Algorithm](#black-box-fcs-algorithm)
	- [4.3 Grey-box FCS Algorithm](#grey-box-fcs-algorithm)
- [5. Input Generation](#input-generation)
	- [5.1 Model-based (Generation-based) Fuzzers](#model-based-generation-based-fuzzer)
	- [5.2 Model-less (Mutation-based) Fuzzers](#model-less-mutation-based-fuzzers)
- [6. Input Evaluation]
- [7. Configuration Updating]
- [8. Related Work]
- [9. Concluding Remarks]

## Introduction
Fuzzing: process of repeatedly running a program with generated inputs that may be syntatically or semantically malformed. <br>

This paper attempts to unifiy this field, to consolidate and distill large amount of progress in fuzzing. <br>

After introducing chosen terminology and model, this paper follows every stage of model fuzzer and present detailed overview of major fuzzers. <br>

## Systemization, Taxonomy, And Test Programs

### Fuzzing & Fuzz Testing
Fuzzing: running a **Program Under Test(PUT)** with **fuzz inputs**. <br>

Fuzz input: An input that **PUT** may not be expecting => PUT may process incorrectly and trigger unintended bahaviour

#### Defenition 1: Fuzzing
Fuzzing: Execution of the PUT using input sampled from an input space (**fuzz input space**) that protudes the expected input space of PUT. <br>

1. It will be common for fuzz input space to contain expected input space, but it is okay for former to not contain latter. <br>
2. Fuzzing normally involves a lot of repitition => "repeated executions" is quite accurate expression <br>
3. Sampling process is **not necesarilly** randomized. <br>

#### Defenition 2: Fuzz Testing
Fuzz Testing: Use of fuzzing to test if a PUT violates correctness policy. 

#### Defenition 3: Fuzzer
Fuzzer: Program that performs fuzz testing on a PUT

#### Defenition 4: Fuzz Campaign
Fuzz Campaign: Specific execution of a fuzzer on a PUT with a specific correctness policy <br>

Running PUT through fuzz campaign is to find bug that violate the specific correctness policy. <br>

Fuzz testing can actually be used to test any policy observable from execution ex: **EM-enforcable** <br>

Bug Oracle: Specific Mechanism that decides whether an execution violates the policy

#### Defenition 5: Bug Oracle
Bug Oracle: Program, perhaps as part of a fuzzer, that determines whether a given execution of the PUT violates a specific correctness policy. <br>

Although fuzz testing is focused on finding policy violation, the techniques can be diverted toward other usage. ex: PerfFuzz that reveal performance problem 

#### Definition 6: Fuzz Configuration
Fuzz configuration: Fuzz configuration of a fuzz algorithm comprises the parameter value that control fuzz algorithm. <br>

Almost all fuzz algorithm depend on some paramters beyond the PUT. Each concrete setting of the parameter is a fuzz configuration <br>

Type of values in a fuzz configuration => depend on the type of the fuzz algorithm. <br>

For example.. <br>

Fuzz algorithm that sends streams of random bytes to the PUT => simple configuration space {(PUT)}. <br>

Sophisticated fuzzers contain algorithms that accept **a set of configurations** and evolve the set over time -> includes adding, removing configurations <br>

For example, CERT BFF varies both **mutation ratio** and the **seed** over the course of a campaign => configuration space is form of {(PUT,s1,r1),(PUT,s2,r2)...} <br>

Seed: Input to the PUT, used to generate test cases byv modifying it. Fuzzers typically maintain a collection of seeds => **seed pool** <br>

Some fuzzers evolve the pool as the fuzz campaign progresses. <br>

A fuzzer is able to store some data within each configuration => coverage-guided fuzzer: Store attained coverage in each configuration 

### Fuzz Testing Algorithm
-Algorithm 1-
```
Input: C, tlimit
Output: B // a finite set of bugs
B ← ∅
C ← PREPROCESS(C)
while telapsed < tlimit ∧ CONTINUE(C) do
	conf ← SCHEDULE(C, telapsed, tlimit)
	tcs ← INPUTGEN(conf)

	// Obug is embedded in a fuzzer
	B', execinfos ← INPUTEVAL(conf, tcs, Obug)
	C ← CONFUPDATE(C, conf, execinfos)
	B ← B ∪ B'
return B
```
Algorithm 1: Generic algorithm for fuzz testing, which imagined to have been implemented in a **model fuzzer**. <br>

Input: A set of fuzz configurations C , timeout t-limit <br>

Output: A set of discovered bugs B <br>

Part 1: **PREPROCESS** function, which executed at the beginning of a fuzz campaign. <br>

Part 2: Loop with five functions => **SCHEDULE**, **INPUTGEN**, **INPUTEVAL**, **CONFUPDATE**, **CONTINUE** <br>

Each iteration of loop => **fuzz iteration**. Each time **INPUTEVAL** executes PUT on a test case => **fuzz run** <br>

#### PREPROCESS (C) -> C
**PREPROCESS** + A set of fuzz configuration => Potentially-modified set of fuz configurations <br>

Depending on the fuzz algorithm, **PREPROCESS** perform various action(ex: insert instrumentation code to PUT, measure exec speed of seed file)

#### SCHEDULE (C, t-elapsed, t-limit) -> conf
**SCHEDULE** + current set of fuzz configurations + current time t-elapsed + timeout t-limit => Select a fuzz configuration to be used for the current iteration

#### INPUTGEN (conf) -> tcs
**INPUTGEN** + fuzz configuration => A set of concrete test cases tcs <br>

When generating tast cases, **INPUTGEN** uses specific parameter in conf. <br>

Some fuzer use a seed in conf for generating test cases, other fuzzers use a model or grammars as a parameter 

#### INPUTEVAL (conf, tcs, O-bug) -> B', execinfos
**INPUTEVAL** + fuzz configuration conf + a set of test cases tcs => Check if the execution violate correctness policy using **Bug Oracle** <br>

Output: Set of bugs found B' + information about each of the fuzz runs execinfos => Used to update the fuzz configurations 

#### CONFUPDATE (C, conf, execinfos) -> C
**CONFUPDATE** + A set of fuzz configurations C + current configuration conf + information about each run execinfos <br>

=> Update the set of fuzz configurations C. Many grey-box fuzzers reduce the number of fuzz configurations in C based on execinfos

#### CONTINUE (C) -> {TRUE, FALSE}
**CONTINUE** + A set of fuzz configurations C => Decide whether a new fuzz iteration should occur. <br>

Usefule to model white-box fuzzers that can terminate when there are no more paths to discover. 

### Taxonomy of Fuzzers
Categorized fuzzers into three groups(based on the granularity of semantics a fuzzer observes in each run) <br>

#### Black-box Fuzzer
black-box: Do not see the internals of the PUT, Can observe only the input/output behavior => **black box** <br>

#### White-box Fuzzer
White-box fuzzing: Generates test cases by analyzing the internals of the PUT + execinfo when executing PUT <br>

Can explore the state space of the PUT systemically <br>

Dynamic Symbolic Execution(variant of symbolic execution) => 
Symbolic and Concrete execution operate concurrently, where concrete program states are used to simplify symbolic constraints <br>

In addition, white box fuzzing: Also been used to describe fuzzers that employ taint analysis <br>

Overhead => much higher than black-box, Partly because of DSE implementation + often DSE and SMT solving <br>

#### Grey-box Fuzzer
Grey-box Fuzzing: Can obtain **some** information internal to the PUT and/or its executions <br>

Does not reason full semantics, instead <br>

1. May perform lightweight static analysis on the PUT <br>

2. Gather dynamic information about its execution such as code coverage <br>

Grey-box fuzzers rely on **approximate**, **imperfect** information -> to gain speed and test more inputs <br>

## PREPROCESS
Some fuzzers prepare the loop by modifying the initial set of fuzz configurations before first fuzz iteration <br>

Such preprocessing is used to... <br>

1. Instrument the PUT <br>

2. Weed out potentially redundant configurations (ex: seed selection) <br>

3. Trim seeds <br>

4. Generate driver applications <br>

5. Prepare a model for future input generation (**INPUTGEN**) ..etc

### Instrumentation
Grey-box, White-box fuzzer -> Can instrument PUT to gather feedback as **INPUTEVAL** performs fuzz runs, or to fuzz the memory content at runtime <br>

Instrumentation => Often the method that collects the most valuable feedback <br>

Program instrumentation: Static or Dynamic <br>

**Static**: Happens before the PUT runs (**PREPROCESS**) <br>

**Dynamic**: Happens while the PUT is running (**INPUTEVAL**) <br>

1. Static Instrumentation <br>

Often performed at compile time on either source code or intermidiate code. Less runtime overhead than dynamic instrumentation <br>

If PUT relies on libraries => have to be separately instrumented, commonly by recompiling them with the same instrumentation <br>

Binary-level instrumentation is also developed <br>

2. Dynamic Instrumention

Performed at runtime => Easily instrument dynamically-linked libraries (ex: DynInst, DynamoRIO, QEMU..) <br>

Fuzzer can support more than one type of instrumentation <br>

For example... <br>

AFL: Supports static instrumentation at the source code level with modified compiler + dynamic instrumentation at the binary level with help of QEMU <br>

Dynamic instrumentation => AFL can instrument <br>

1. Executable code in the PUT itself => default setting <br>

2. Executable code in the PUT and any external libraries(optional)

#### Execution Feedback 
Grey-box Fuzzer + Execution feeback => evolve test cases <br>

LibFuzzer, AFL, descendants: Compute **branch coverage** by instrumenting every branch instruction in the PUT <br>

However, branch coverage information is stored in a compact bit vector => Can become inaccurate due to path collision <br>

Syzkaller: Use **node coverage** as execution feedback <-> Hongfuzz allow users to choose which execution feedback to use

#### Thread Scheduling
Race condition -> Non-deterministic behavior -> Difficult to trigger <br>

By explicitly controlling how threads are **scheduled** => Can trigger non-deterministic behaviors 

#### In-Memory Fuzzing
When testing large program -> Better to fuzz **only a portion** of the PUT (Not re-spawning entire process) <br>

For example... <br>

Complex applications(ex: GUI) => Can take snapshot of the PUT after GUI is initialized <br>

-In-Memory API Fuzzing- <br>

Performing in-memory fuzzing on a function **without restoring the state of the PUT after iteration**. <br>

Efficient, but suffers from unsound bug, crahses (Not reproducible) 

### Seed Selection
Fuzzers receive a set of fuzz configurations controlling behaviors of the fuzzing algorithm <br>

Seeds for mutation-based fuzzers => Can have infinite domain(ex: MP3 file) <br>

Seed Selection Problem: How to choose, reduce seed for fuzzing amoung abounded number of seeds <br>

Common approach: **minset** => Finds a minimal set of seeds that maximizes a coverage metric such as node coverage <br>

For example, suppose current set of configuration C that has two seeds that cover following address <br>

{s1 -> (10,20)} , {s2 -> (20, 30)} <br>

If thrid seed looks like {s3 -> (10, 20, 30)} => Better to test s3 instead of s1, s2(Test same set of code, half exec time) <br>

This step can also be part of **CONFUPDATE** => Useful for fuzzers introducing new seeds into seed pool throughout campaign <br>

### Seed Trimming
Smaller seeds => Consume less memory, entail higher throughput <br>

Seed Trimming: Reduce the size of seeds before fuzzing, Can happen prior to main fuzzing loop in **PREPROCESS** or **CONFUPDATE** <br>

AFL: Use code coverage instrumentation to iteratively remove a portion of seed as long as the modified seed achieves the same coverage <br>

MoonShine extends Syzkaller to reduce the size of seeds while preserving the dependencies between calls (detected using a static analysis)

### Preparing a Driver Application
Difficult to fuzz the PUT directly => Prepare driver for fuzzing <br>

Done only once at the beginning of a fuzz campaign, but largely manual <br>

Ex: Target is a libary => Need to prepare for a driver program that calls functions in the library 

## SCHEDULING 
Scheduling => Selecting a fuzz configuration for the next fuzz iteration <br>

Context of a fuzz configuration depends on the type of the fuzzer. <br>

For example, for advanced fuzzer such as BFF, AFLFast, innovative scheduling algorithms are major factors

### The Fuzz Configuration Scheduling(FCS) Problem
Goal of scheduling => Analyze currently available information about the configurations and pick one that is more likely to lead to the most favorable outcome <br>

Fundamentally, every scheduling algorithm confronts same problem => **exploration vs exploitation** <br>

- Explore: Spend time on gathering more accurate information on each configuration to inform future decisions

- Exploit: Spend time on fuzzing the configurations that are currently believed to lead to more favorable outcome 

### Black-box FCS Algorithm 
In Black-box setting, only information for FCS algorithm => Fuzz outcome of a configuration (number of crashes and bugs, amount of time spent... ) <br>

CERT BFF black-box mutational fuzzer => Favor configurations with higher observed success probabilities (#unique crashes / #runs) <br>

Improved:
1. Refine model to become **Weighted Coupon Collector's Problem with Unknown Weights** -> learns decaying upper-bound on the success probability of each trial 

2. Apllied **multi-armed bandit** algorithms to fuzzing -> Common copying strategy when faced with exploration vs exploitation 

3. Normalized success probability of a configuration by the time already spent -> Prefer faster configuration

4. Redefined fuzz iteration to run for fized amount of time -> Deprioritizing slower configurations 

### Grey-box FCS Algorithm
In Grey-box setting, FCS algorithm can choose to use a richer set of information about each configuration (coverage attained when fuzzing a configuration) <br>

AFL => Forefunner of this categorty + based on Evolutionary Algorithm(EA) <br>

EA => mainatain population of configuration, each with some value of **fitness**, EA selects fit configurations and apply them to genetic transformations (ex: mutation) and recombination to produce **offspring** <br>

Hypothesis => Theses produced configurations(from offsping) are more likeyl to fit <br>

To understand FCS in context of EA...

1. Have to define what makes a configuration fit

2. Have to define how configurations are selected

3. Have to define how a selected configuration is used. 

AFL => Considers configuration that contains fastest, smallest input to be fit. <br> 

Once selected, AFL allocates more runs to configurations which are fastest and have higher branch coverage <br>

AFLFast improved AFL in three aspects

1. It modifies configuration fitness setting and selection to prioritize exploration of new and rare paths 

2. AFLFast fuzzes a selected configuration a variable number of times detemined by **power schedule**. <br> **FAST power schedule** => starts with small **energy** value to ensure initial exploration amoung configurations and increases exponentially up to a limit to quickly ensure sufficient exploitation

3. Normalizes energy by the number of generated inputs that execises the same path => promoting explorations of less-frequently fuzzed configuration

## Input Generation
Technique used for input generation => Most influential design decisions in a fuzzer <br>

1. Generation-based fuzzers
Produce test cases based on the given model that describes input expected by the PUT => **model-based fuzzer** 

2. Mutation-based fuzzers
Considered to be **model-less**, because seeds are merely example inputs + Do not completely describe expected input space of PUT 

### Model-based (Generation-based) fuzzer
Model-based => generate test cases based on given model (ex: grammar precisely characterizing input format, magic value of file types)

#### Predefined Model
Some fuzzers use a model that can be configured by the user <br>

- Peach, PROTOS, Dharma => Take specification provided by user 

- Autodafe, Sulley, SPIKE, SPIKEfile, Libfuzzer => Expose APIs that allow analysts to create their own input model 

- Tavor => Take in an input specification written in Extended Backus-Naur form -> generate test cases conforming to the grammar 

- network protocol fuzzer(PROTOS, SNOOZE, TFuzz) => Take in protocol specification

- Kernel API fuzzer(trinity, syzkaller, syscallfuzzer..) => Define input model in the form of syscall template 

Other model-based fuzzers target a specific language or gramma

- cross_fuzz, DOMfuzz => generate random Document Object Model object

- jsfunfuzz => produce random, but syntatically-correct JavaScript code based on own grammar model 

#### Inferred Model
Inferring model rather than relying on predefined/user-provided model <br>

Similar to instrumentation, model inference can occur either in **PREPROCESS**, **CONFUPDATE** <br>

- In PREPROCESS:
Some fuzzers infer the model as a preprocessing step<br>
TestMiner: searches for the data available in the PUT to predict suitable inputs <br>
Skyfire: Given a set of seeds and a grammar => Uses data-driven approach to infer a probabilistic context-sensitive grammar and then uses it to generate new sets of seeds <br>
IMF: Learns a kernel API model by analyzing system API logs => Produce C code that invoke a sequence of API calls using the inferred model 

- In CONFUPDATE:
Other fuzzers can update their model after each fuzz iteration<br>
PULSAR: Aumatically infers a network protocol model from a set of captured network packets generated from a program => Internally builds a state machine and maps which message token is correlated with a state. The information is later used to generate test cases that cover more states <br>
GLADE: Synthesizes a context-free grammar from a set of I/O samples and fuzzes the PUT using inferred grammar <br>

#### Encoder Model
Fuzzing is often used to test **decoder** programs which parse certain file format <br>

Many file formats have => corresponding **encode** program -> implicit model of file format <br>

MutaGen: Leverage implicit model contained in encoder program to generate new test cases. => Mutate **encoder program** not test cases <br>

To produce test case => MutaGen computes **dynamic program slice** of the encoder program => Program slice will slightly change the behavior of encoder program -> Slightly malform test case

### Model-less (Mutation-based) Fuzzers
Classic random testing => Inefficient for specific patch condition
```
if (input == 42)
```
Satisfying this condition randomly is too hard => Test case will be rejected before entering deep part of system <br>

seed => Input to the PUT, used to generate test cases by modifying the seed. <br>

By mutating only a fraction of seed(valid file) -> Can generate test cases that is mostly valid, but also contain abnormal values 

#### Bit-Flipping
Common technique used by many model-less fuzzers -> flip fixed/random number of bits <br>

**mutation ratio** -> User-configurable parameter that determines the number of bit to flip for a single execution of **INPUTGEN**. K random bits in a given N-bit seed => K/N mutation ratio<br>

Symfuzz -> Showed fuzzing performance is sensitive to mutation ratio + There is not a single ratio suitable for all PUTs <br>

BFF, FOE -> Use an exponentially scaled set of mutation ratios + Allocate more iteration to ratios that proved to be statistically effective 

#### Arithmetic Mutation
AFL, HongFuzz -> 