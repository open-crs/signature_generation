cmd_/home/feather/student/licenta/syscall_hooking/modules.order := {   echo /home/feather/student/licenta/syscall_hooking/hooking.ko; :; } | awk '!x[$$0]++' - > /home/feather/student/licenta/syscall_hooking/modules.order
