Output demo/ext-authz-story.gif
Output demo/ext-authz-story.mp4

Set Shell "bash"
Set FontFamily "Menlo"
Set FontSize 14
Set Width 1280
Set Height 860
Set Padding 22
Set Framerate 24
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set TypingSpeed 30ms

Hide
Type "export PS1='$ '"
Enter
Type "clear"
Enter
Show

Sleep 600ms
Type "./target/debug/ext-authz-demo demo --story --pause-ms 450"
Sleep 500ms
Enter
Sleep 16s
