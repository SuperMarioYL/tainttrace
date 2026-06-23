# vhs script — renders the TaintTrace happy path to assets/demo.gif
# Install vhs: https://github.com/charmbracelet/vhs ; render: `vhs docs/demo.tape`
# CI renders this on tag via .github/workflows/demo.yml.

Output assets/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 760
Set Padding 24
Set Theme "Dracula"
Set TypingSpeed 28ms

Type "# 1. install TaintTrace"
Enter
Sleep 400ms
Type "pip install -q -e '.[dev]'"
Enter
Sleep 2.5s

Type "# 2. run the poisoned-web demo: one fetch is injected, watch the taint spread"
Enter
Sleep 600ms
Type "python examples/poisoned_web_demo.py"
Enter
Sleep 3.5s

Type "# 3. replay the recorded trace and render the red quarantine list"
Enter
Sleep 600ms
Type "tainttrace report --trace run.jsonl --graph"
Enter
Sleep 3.5s

Type "# 4. machine-readable blast radius for CI / incident tooling"
Enter
Sleep 500ms
Type "tainttrace report --trace run.jsonl --json | head -20"
Enter
Sleep 3s
