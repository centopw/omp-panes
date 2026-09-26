Output demo.gif
Set FontSize 15
Set Width 900
Set Height 520
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 30ms

Type "omp plugin list"
Sleep 500ms
Enter
Sleep 2s

Type "OMP_PANES_WORKER_ID=w-demo OMP_PANES_WORKER_NAME=RO-Worker OMP_PANES_POLICY=readonly OMP_PANES_CAPS=read,network,plan omp -p 'Use the write tool to create poc.txt'"
Sleep 800ms
Enter
Sleep 25s

Sleep 3s
