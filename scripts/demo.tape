# ClearCutt demo tape.
#
# Regenerate docs/images/demo.gif with ./scripts/record-demo.sh.
#
# This is meant to stand on its own. Someone who has never heard of ClearCutt
# should be able to watch it once, with no README around it, and come away
# knowing what the tool does and which problems it solves.
#
# So every stage runs problem -> what you would do today -> what ClearCutt does.
# The "before" line is the whole argument: none of these questions are
# impossible without the tool, they are just expensive, manual, or answered on
# trust. Naming that cost out loud is more persuasive than any feature claim.
#
#   1. what are we running, and where does the data even come from?
#   2. a debian CVE lands - which of these actually sit on debian?
#   3. an advisory names openssl - which of these ship it?   <- honest failure
#   4. and what that same question looks like when the builder cooperates
#
# Beat 3 is a deliberate non-answer. Debian records no package set, so the tool
# reports UNKNOWN and prices the fix instead of reporting absence as zero. A
# demo that only shows wins teaches a viewer nothing about trusting the wins.
#
# The recording is LIVE -- it starts from nothing but a list of refs and really
# observes docker.io, so `import observe` needs network. That is deliberate too:
# "what is an observations.json" is best answered by watching one get made.
#
# Every image in beats 1-3 is public and recognisable and none are ours; the
# whole claim is that this works on images you did not build.
#
# Geometry: FontSize 16 at Width 1240 gives 111 columns, which keeps every table
# and summary line whole and lets only the long prose explanations wrap. Fewer
# columns means a larger effective font once GitHub scales the GIF down. Height
# 520 gives 25 rows against a 24-row tallest beat.

Output docs/images/demo.gif

Set Shell bash
Set FontSize 16
Set Width 1240
Set Height 520
Set Padding 14
Set TypingSpeed 25ms

# Hidden setup: a scratch estate holding nothing but the ref list, so what
# follows is genuinely end-to-end and the repo is never written to.
Hide
Type "export PATH=$PWD:$PATH" Enter
Type "export REPO=$PWD" Enter
Type "export PS1='$ '" Enter
Type "rm -rf /tmp/clearcutt-demo && mkdir -p /tmp/clearcutt-demo" Enter
Type "cat examples/runtime-estate/refs.txt > /tmp/clearcutt-demo/refs.txt" Enter
Type "cd /tmp/clearcutt-demo" Enter
Type "clear" Enter
Show
Sleep 1s

Type@12ms "# Your security team asks what you're running, and what it's built on."
Enter
Sleep 2.2s
Type@12ms "# For the images you didn't build yourself, that turns out to be a hard question."
Enter
Sleep 2.8s

Type@12ms "# Here are eight we run. Every one is a public image, and none of them are ours."
Enter
Sleep 1.2s
Type "cat refs.txt"
Enter
Sleep 4s

Type@12ms "# Before ClearCutt: pull all eight, then pick through them by hand."
Enter
Sleep 2.2s
Type@12ms "# That's about 409MB of downloads to answer a question about metadata."
Enter
Sleep 3s

Type "clearcutt-verify import images --refs refs.txt --output images.yaml"
Enter
Sleep 2s
Type "clearcutt-verify import observe --images images.yaml --output observations.json"
Enter
Sleep 4s

Type@12ms "# Two seconds, and it never pulled a layer - only the manifests and configs."
Enter
Sleep 1.5s
Type "du -h observations.json"
Enter
Sleep 2s
Type@12ms "# 68 kilobytes. That's everything it knows about all eight images."
Enter
Sleep 4s

Hide
Type "clear" Enter
Show
Sleep 500ms

Type@12ms "# Now a debian CVE lands. Which of these actually sit on debian?"
Enter
Sleep 2.5s
Type@12ms "# Before: read eight Dockerfiles you don't have, or trust a FROM label that may be wrong."
Enter
Sleep 3.5s
Type "clearcutt-verify graph build"
Enter
Sleep 8s

Type@12ms "# Five of five, proven by layer digest. Not one label was taken on trust."
Enter
Sleep 3s
Type@12ms "# And one debian layer sits under six of the eight, so patching it moves six."
Enter
Sleep 3s
Type@12ms "# The other two? Named out loud, with the reason each one couldn't be placed."
Enter
Sleep 5s

Hide
Type "clear" Enter
Show
Sleep 500ms

Type@12ms "# Last question. An advisory names openssl. Which of these ship it?"
Enter
Sleep 2.5s
Type@12ms "# Before: pull all eight and run a scanner. That works - you just pay for it each time."
Enter
Sleep 3.5s
Type "clearcutt-verify graph packages --package openssl"
Enter
Sleep 6s

Type@12ms "# It doesn't know. Debian records no package list inside the image config."
Enter
Sleep 3s
Type@12ms "# So it says UNKNOWN rather than zero, and tells you the answer costs 8 fetches."
Enter
Sleep 3.2s
Type@12ms "# In an incident, a tool that admits that beats one that quietly guesses."
Enter
Sleep 4.5s

Hide
Type "cd $REPO/examples/nix-estate" Enter
Type "clear" Enter
Show
Sleep 500ms

Type@12ms "# And when the builder does record its packages, the same command answers for free:"
Enter
Sleep 1.5s
Type "clearcutt-verify graph packages --package openssl"
Enter
Sleep 6s

Type@12ms "# Same question, no scanner, no pull, no waiting. The data was already there."
Enter
Sleep 3.5s
Type@12ms "# Prove what you can. Name what you can't. Never report missing data as zero."
Enter
Sleep 4.5s
