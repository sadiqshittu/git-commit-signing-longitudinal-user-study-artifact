# PROJECT: USABLE KEY MANAGEMENT (PART 2)

Throughout the second half of this semester, you have been using Git commit signing. In this project,
you will be reflecting on that experience. You will also have the opportunity to experience synchronizing
signing keys across multiple machines.

## Requirements

In Part 2 of this project, you will complete two activities. You will then write a report about your
experiences in each activity. In this report, you will also reflect on your experience using commit signing
throughout the second half of the semester. Finally, you will complete several thought problems
regarding Git commit signing security.

### Activity 1

In this activity, you will add a signed commit to the repository you created in Part 1. This commit must be
signed on a different device than the one you used to sign the commits in Part 1 of this project. More
specifically:

1. If you used a personal computer (i.e., not a [REDACTED] machine) to sign your commit in Part 1,
you will need to sign the commit for this activity using a [REDACTED] machine; **OR**
2. If you used a [REDACTED] machine to sign your commit in Part 1, you will need to sign the commit
for this activity using a personal computer (i.e., not a [REDACTED] machine).

The signed commit should include a file called **Part 2.txt** that indicates what machine you used to sign
the commit in Part 1, and what machine you are using to sign the commit in Part 2. As you did in Part 1,
verify that the commit is signed. *If you lost access to your repository from Part 1, you can download it
from your Canvas submission for Part 1.*

### Activity 2

Pretend you are interested in using an open-source library in a project at work. However, you've also
read that some repositories contain malicious code secretly added by attackers. To ensure the library is
safe to use, you have contacted the project maintainers. The maintainers have sent you their private
keys, allowing you to check that all commits come from the developers. Your task is to (1) clone the
repository, (2) analyze its commit history to determine whether you would feel safe including this library
in your work project.

Repository: [REDACTED]

Developer 1: [REDACTED]
[REDACTED] [REDACTED]

Developer 2: [REDACTED]
[REDACTED] [REDACTED]

## Report Contents

### Section 1—Activity 1

- How long did it take you to complete this activity?
- What steps did you take to complete the activity?
  - Include details about anything you attempted that ultimately did not work.
  - Include screenshots if you think that would be helpful.
- Identify the tools you used.
  - Also, include details about any tools you ultimately abandoned.
  - Describe what went well with these tools and what was challenging.
- Describe what information sources you used and how helpful (or unhelpful) they were.
  - Why did you need to use them?
  - Why were they helpful (or unhelpful)?
- To complete this activity, you could either copy your private key to the new machine or generate a
new key pair for the new machine. Which approach did you choose? Why?
- Answer the following questions:
  - What were the easiest one or two steps in setting up Git commit signing on a second device?
Why were they the easiest?
  - What were the hardest one or two steps in setting up Git commit signing on a second device?
Why were they the hardest?
  - What would you change about the process for setting up Git commit signing on a second
device, if anything?

Answer the after-scenario questionnaire (ASQ) by indicating how much you agree with the
following statements on a scale of 1 (strongly disagree) to 7 (strongly agree).

- Overall, I am satisfied with the ease of setting up and using commit signing on a second
device.
- Overall, I am satisfied with the amount of time it took to set up and use Git commit signing on a
second device.
- Overall, I am satisfied with the support information (online help, messages, documentation) I
found when setting up and using commit signing on a second device.

Provide any other feedback you have about this activity or Git commit signing on a second device.

### Section 2—Activity 2

- Did you identify any commits that you think are problematic?
  - If so, what was problematic about that commit?
  - Provide these details for each commit you believe is problematic.
- How long did it take you to complete this activity?
- What steps did you take to complete the activity?
  - Include details about anything you attempted that ultimately did not work.
  - Include screenshots if you think that would be helpful.
- Identify the tools you used.
  - Also, include details about any tools you ultimately abandoned.
  - Describe what went well with these tools and what was challenging.
- Describe what information sources you used and how helpful (or unhelpful) they were.
  - Why did you need to use them?
  - Why were they helpful (or unhelpful)?
- Answer the following questions:
  - What were the easiest one or two steps in analyzing the Git commit history? Why were they
the easiest?
  - What were the hardest one or two steps in analyzing the Git commit history? Why were they
the hardest?
  - What would you change about the process of analyzing the Git commit history, if anything?

Answer the after-scenario questionnaire (ASQ) by indicating how much you agree with the
following statements on a scale of 1 (strongly disagree) to 7 (strongly agree).

- Overall, I am satisfied with the ease of analyzing the Git commit history.
- Overall, I am satisfied with the amount of time it took to analyzing the Git commit history.
- Overall, I am satisfied with the support information (online help, messages, documentation) I
found when analyzing the Git commit history.

Provide any other feedback you have about this activity or analyzing Git commit histories.

### Section 3—Semester-long reflection

For this section, please reflect on your experience using Git commit signing in the second half of
the semester.

- Where did you store your private key? How was it secured?
- Did you change anything about how you signed commits throughout the second half of the
semester? If so, what changes did you make? Why did you make those changes?
- Do you plan to start signing your Git commits outside of this class? Why or why not?

Answer the system usability scale (SUS) questions by indicating how much you agree with the
following statements on a scale of 1 (strongly agree) to 5 (strongly disagree).

- I think that I would have no problem using Git commit signing frequently.
- I found using Git commit signing unnecessarily complex.
- I thought that using Git commit signing was easy.
- I think that I would need the support of a technical support staff to use Git commit signing in the
future.
- I found the various functions for using Git commit signing to be well-integrated.
- I thought there was too much inconsistency in using Git commit signing.
- I would imagine that most people would learn to use Git commit signing very quickly.
- I found using Git commit signing to be very cumbersome.
- I felt very confident using Git commit signing.
- I needed to learn a lot of things before I could get going with using Git commit signing.

Answer the following questions:

- What were the easiest steps to set up Git commit signing, sign a commit, or verify a commit?
Why were they the easiest?
- What were the hardest one or two steps in setting up Git commit signing, signing a commit, or
verifying a commit? Why were they the hardest?
- What would you change about the setup process, if anything?
- How did the usability of setting up git commit signing compare to the usability of using it
throughout the second half of the semester?

Provide any other feedback you have about Git commit signing.

### Section 4—Thought exercises

In this section, you will complete several thought exercises. You will receive full credit for whatever you put down. I'm not looking for you to get the "right" answer, but rather for you to share your thoughts based on what you've learned this semester and your experiences using Git commit signing.

- Are there any security benefits or drawbacks to using Git commit signing as compared to
unsigned commits? If so, what are they?
- To use Git commit signing on multiple devices, you could either synchronize your existing signing
key to the new machine or generate a new signing key for that machine. Each of these
approaches has different potential security implications. What do you think the security benefits or
drawbacks of each approach are?
- If you were to lose your Git signing private key, what would you need to do to continue signing
commits? Are there any security concerns with your proposed workflow? If so, how could they be
addressed (you can answer that you don't know)?
- If you were to have your Git signing private key stolen, what would you need to do to ensure the
security of your repository? Are there any security concerns with your proposed workflow? If so,
how could they be addressed (you can answer that you don't know)?
- Consider an open source project that's widely used, and attackers would like to get their code into
this repository. What might attackers try to do to compromise that repository? What practices
would you recommend that developers of this repo take to ensure that no malicious commits are
added to their codebase?

## Getting Started and Getting Help

As the purpose of this project is to give you experience with a real-world cryptosystem, neither the
instructor nor the TAs will tell you how to complete this task. However, you are free to use any online
information source you want. You are also free to use whatever tools you wish to complete this
project.

## [REDACTED] Lab

To complete this project, you will need to access the browser on a [REDACTED] machine. While this can be done over SSH with X forwarding, for most students, it will be easier to complete this project physically at a [REDACTED] machine. The [REDACTED] lab is in [REDACTED], and the [REDACTED] lab is in [REDACTED]. Occasionally, these labs are in use by other classes.

## Grading Rubric

- 10 points for completing section 1.
- 10 points for completing section 2.
- 15 points for completing section 3.
- 15 points for completing section 4.

Throughout, the report should be well-written, answering the questions listed in the requirements section. Also, if you do not setup Git commit signing on a second machine, at most you can receive half points for the report.

## Submission

Submit your written report as a PDF file to Canvas.
