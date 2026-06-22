# litevirt README terminal cast — reproducible with:  vhs docs/demo/demo.tape
# (run from the repo root; uses the generic demo shim in docs/demo/lv)
Output docs/img/demo.gif

Set Shell bash
Set FontSize 19
Set Width 1180
Set Height 640
Set Padding 22
Set Theme "Dracula"
Set TypingSpeed 55ms

# Clean, minimal prompt; put the demo shim first on PATH (hidden setup).
Hide
Type 'export PS1="$ "; export PATH="$PWD/docs/demo:$PATH"; rm -f /tmp/.lvdemo-migrated'
Enter
Type 'clear'
Enter
Show
Ctrl+L
Sleep 800ms

Type "lv host ls"
Sleep 500ms
Enter
Sleep 2.2s

Type "lv run --name web-01 --image ubuntu-24.04 --cpu 2 --memory 2048"
Sleep 500ms
Enter
Sleep 2s

Type "lv migrate web-01 node-3"
Sleep 500ms
Enter
Sleep 2.8s

Type "lv ls"
Sleep 500ms
Enter
Sleep 3s
