# WIL

# PROJECT 2 : USER PROGRAMS

## TOPICS

- Argument Passing
- User Memory
- System Calls
- Process Termination Messages
- Denying Writes to Executables
- ~~Extend File Descriptor (Extra)~~

## 일별 진행목록

|  | 진행 사항 |
| --- | --- |
| 금 ~ 일 | - 일정 수립<br />- 이론 학습(gitbook - introduction 및 argument passing, CSAPP 8.2 ~ 8.4) |
| 월 | - argument passing 구현 |
| 화 | - argument passing 리팩토링<br />- 이론 학습(gitbook - system call) |
| 수 | - system call 구현 (halt, file system 관련 system call) |
| 목 | - file system 관련 system call 구현 완료<br />- wait, exec, fork, exit 구현 시작 |
| 금 ~ 일 | - 테스트 완료<br />- system call 코드 수정 |

## 구현내용 회고

1. `process_fork`
    1. 부모의 스택 영역을 복사해왔음에도, 부모 프로세스에선 자식의 `pid`를, 자식 프로세스에선 `pid` `0`을 반환하여 분기했던 파트가 기억에 남는다.

        ```c
        (생략...)
        tid_t pid = fork();
        if (pid)
        {
        	// 부모의 코드가 실행될 영역
        } else
        {
        	// 자식의 코드가 실행될 영역
        }
        ```

        스택영역을 추상화한 구조체인 `intr_frame`의 레지스터 `rax`에 자식 프로세스에서 마무리한 작업 반환할 값(`0`)을 저장해주었다. 이를 통해서 추상적으로만 보였던 커널스택과 유저스택에 대한 이해가 조금 명확해 졌고 기억하고자 WIL에 쓰게 됐다.

    2. `process_fork`에서 자식이 포크 과정 중 이상이 있을 때 자신의 종료 상태를 명시적으로 반환하지 않는데, 부모가 그 종료 상태를 어떻게 캐치해서 `TID_ERROR`을 반환할 수 있을까?

        ```c
        if (tid == -1) {
        	return TID_ERROR;
        }
        
        struct thread *child_thread = get_child_with_id(tid);
        
        sema_down(&child_thread->fork_sema);
        
        if (child_thread->exit_status == -1) {
         	return TID_ERROR;
        }
        
        return tid;
        ```

        `thread` 구조체에 `exit_status` 필드를 추가하여 종료 상태를 관리할 수 있다.

    3. `__do_fork`에서 부모의 인터럽트 프레임을 어떻게 넘겨줄 수 있을까
        - `thread` 구조체에 원래부터 정의되어 있던 `tf` 필드에 `syscall handler`의 인자로 들어오는 인터럽트 프레임을 `memcpy`로 복사하려고 했으나, 이렇게 복사한 값이 `__do_fork`에서 다른 값으로 변경돼서 실패 → 쓰레드 스위칭 될 때마다 `tf` 값이 바뀌기 때문이었을 것

            ```c
            /* Owned by thread.c. */
            struct intr_frame tf; /* Information for switching */
            ```

        - `thread` 구조체에 `userland context`를 저장하기 위한 용도로 새로운 필드를 추가하고, `syscall handler`의 인자로 들어오는 인터럽트 프레임을 여기에 복사

            ```c
            struct intr_frame user_tf;  /* Save the userland context. */
            ```

            ```c
            void
            syscall_handler (struct intr_frame *f) {
            	(...중략)
            
            	case SYS_FORK:
            			check_address(f->R.rdi);
            			intr_frame_cpy(f);
            			f->R.rax = fork(f->R.rdi);
            			break;
            
            	(...생략)
            }
            
            void
            intr_frame_cpy(struct intr_frame *f) {
            	struct thread *curr_thread = thread_current();
            
            	memcpy(&curr_thread->user_tf, f, sizeof(struct intr_frame));
            }
            ```

            ```c
            static void
            __do_fork (void *aux) {
            	(...중략)
            
            	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
            	struct intr_frame *parent_if = &parent->user_tf;
            
            	(...생략)
            }
            ```


2. multi-oom

   - 메모리 누수를 잡자
       - `palloc_free_page`, `file_close`
   - 주석에 답이 있었다.

       ```c
       /* Open as many files as we can, up to fdmax.
       	 Depending on how file descriptors are allocated inside
       	 the kernel, open() may fail if the kernel is low on memory.
       	 A low-memory condition in open() should not lead to the
       	 termination of the process.  */
       ```

       ```c
       int
       open (const char *file) {
       
       	struct thread *curr_t = thread_current();
       	struct file *f = filesys_open(file);
       
       	int fd = get_next_fd(curr_t->fdt);
       	if (fd == -1)
       	{
       		// return -1;
       		file_close(f);
       	}
       
       	curr_t->next_fd = fd;
       
       	if (f) {
       		curr_t->fdt[fd] = f;
       		return fd;
       	}
       	else {
       		return -1;
       	}
       }
       ```


## 느낀 점

- 👨‍🎤  주홍: 중요한 건 꺾이지 않는 마음
- 🧑🏻‍🎤  황석: 레퍼런스가 도움이 될 순 있지만 우리의 길과 정답을 찾는 게 중요한 것 같다.
- 👩🏻‍💻  예인: 구현은 함께, 디버깅은 각자

---
Brand new pintos for Operating Systems and Lab (CS330), KAIST, by Youngjin Kwon.

The manual is available at https://casys-kaist.github.io/pintos-kaist/.
