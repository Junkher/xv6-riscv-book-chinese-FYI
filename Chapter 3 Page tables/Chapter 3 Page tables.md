## Chapter 3 Page tables

>Page tables are the mechanism through which the operating system provides each process with its own private address space and memory.
操作系统通过页表为每个进程提供私有地址空间和内存。

页表决定内存地址，以及能够访问的物理内存。这就让xv6能够隔离不同进程的地址空间，从而复用物理内存。页表也提供了a level of indirection让xv6能使用这些技巧：将同一内存(**trampoline page**)映射到多个地址空间，用无映射的页来保护内核栈和用户栈。
下面的章节将解释RISC-V硬件实现的页表以及xv6如何利用页表。

---

### 3.1 Paging hardware

- PTE(Page Tavle Entries)
- PA(Physical Address)
- VA(Virtual Address)
- PPN(Physical Page Number)

RISC-V指令(包括内核和用户)操作虚拟地址。机器的RAM，或者说物理内存，是通过物理地址来索引的。RISC-V的页表硬件通过从虚拟地址到物理地址的映射将这两者连接起来。

xv6在Sv39 RISC-V运行，这意味着只有低39位虚拟地址被使用，而高24位则未被使用。在Sv39的配置中，RISC-V的页表逻辑上是$2^{27}$个页表项(PTE)的数组。
每一个页表项包含44位的物理页号(PPN)和一些标志位(flags)。
页表硬件使用虚拟地址39位中的高27位来在页表中索引一个PTE，剩余的低12位在后面组成PA时会被直接复制。
PA由索引到的PTE中44位的PPN和源VA的低12位组成。

> A page table gives the operating system control over virtual-to-physical address translations at the granularity of aligned chunks of 4096($2^{12}$) bytes. Such a chunk is called a page.
操作系统通过页表控制VA到PA的转换，这种转换的粒度是4096($2^{12}$)字节的块，这样的块统称为页。

在Sv39 RISC-V中，高25位VA并不用于做转换；在将来，RISC-V可能使用这些位来定义更多级别的转换。PA同样有增长空间。在PTE的格式中还有10bit未被使用(目前是44位PPN+10位flags)。

![](../img/3/Pasted%20image%2020220516202844.png)


而根据Fig3.2，实际上的转换有三个步骤。

![](../img/3/Pasted%20image%2020220516211620.png)

页表以三级树的形式储存在PA中，树的根节点是一个包含512个PTE的页表，保存着下一级页表页（一个页刚好装下一个页表）的PA。而这些页表又包含512个PTE对应最后一级页表。分页硬件使用VA中高27位中的前9位来选择根页表(L2)中的PTE，中间9位选择下一级页表(L1)的PTE，最后9位选择最后一级页表(L0)中的PTE

如果任何一个PTE转换的PA不存在，分页硬件就会抛出页异常(page-fault exception)，将其交给内核处理(见章节4)。**三级页表的结构允许页表丢弃完整的页表页因为大多数的VA是没有被映射的。

每个PTE包含的标志位告诉分页硬件VA允许如何被使用。

- PTE_V indicates whether the PTE is present: if it is not set, a reference to the page causes an exception (i.e. is not allowed). 
- PTE_R controls whether instructions are allowed to *read* to the page.
- PTE_W controls whether instructions are allowed to *write* to the page. 
- PTE_X controls whether the CPU may interpret the content of the page as instructions and execute them.
- PTE_U controls whether instructions in *user mode* are allowed to access the page; if PTE_U is not set, the PTE can be used only in supervisor mode

为了告诉分页硬件使用页表，内核必须将根页表页的PA写进*satp寄存器*。CPU将会使用satp指向的页表来转换指令中的地址。每个CPU都有各自的satp，因此不同的CPU能够运行不同的进程，而每个进程都有各自的页表所描述的私有地址空间。

>Physical memory refers to storage cells in DRAM. A byte of physical
memory has an address, called a physical address.
物理内存指在DRAM中的储存单元们，每个字节的物理内存都有一个地址，称为物理地址PA。

指令只会使用VA，通过分页硬件来转换为PA，再发送到DRAM来读写数据。
>Unlike physical memory and virtual addresses, virtual memory isn’t a physical object, but refers to the collection of abstractions and mechanisms the kernel provides to manage physical memory and virtual addresses.
跟物理内存和虚拟地址不同，虚拟内存并非是物理实体，而是内核管理物理内存和虚拟地址抽象集合


---

### 3.2 Kernel addree space

xv6为每个进程维护了一个页表，用于描述进程的用户地址空间。另外还有一张页表表示内核的地址空间。
> The kernel configures the layout of its address space to give itself access to physical memory and various hardware resources at predictable virtual addresses.
内核配置它自己的地址空间让其他能访问物理内存和在可预测的虚拟地址上的不同的硬件资源。

(kernel/memlayout.h)声明了xv6内核内存布局的常量。

![](../img/3/Pasted%20image%2020220516211856.png)

QEMU模拟了一台计算机，RAM(physical memory)的起始地址上0x80000000一直到0x86400000(PHYSTOP)。
QEMU同样模拟了IO设备比如硬盘接口，QEMU将这些设备的接口作为内存映射控制寄存器(在0x8000000以下的物理地址空间)暴露给软件。内核可以通过读写这些特殊的物理地址来实现与其他设备的交互（详见章节4）

>物理地址空间，一部分给物理RAM（内存）用，一部分给总线（挂着很多设备）用，这是由硬件设计来决定的


内核通过直接映射来获得RAM和内存映射设备寄存器，也就是虚拟地址等同于物理地址。举个例子，内核位于KERNBASE=0x8000000的虚拟地址空间和物理内存中。直接映射简化从物理内存中读写的内核代码。比如，fork为子进程分配用户内存时，分配器返回内存的物理地址；fork可以直接使用这个地址作为虚拟地址将父进程的用户内存复制到子进程。

但也有一些内核虚拟地址并不是被直接映射：

- The trampoline page. 它位于虚拟地址空间的顶部，用户的页表也有相同的映射。章节4将会讨论**trampoline page**的作用，但我们可以发现有趣的是，物理页 (holding the trampoline code)被映射了两次。一次映射到虚拟地址空间的顶部，一次是直接映射，

- The kernel stack pages. 内核栈，每个进程都有各自的内核栈，它们都位于虚拟地址空间的高地址处，xv6能够预留一些无映射的保护页。这些保护页对应的PTE是无效的(PTE_V not set)，因此如果内核栈溢出，就会导致抛出异常，如果没有保护页，而可能会覆写其他的内核内存，导致错误的操作。所有，保护页的panic crash相对而言更能被接受。

>While the kernel uses its stacks via the high-memory mappings, they are also accessible to the kernel through a direct-mapped address. An alternate design might have just the direct mapping,
and use the stacks at the direct-mapped address. In that arrangement, however, providing guard pages would involve unmapping virtual addresses that would otherwise refer to physical memory,
which would then be hard to use. The kernel maps the pages for the trampoline and the kernel text with the permissions PTE_R
and PTE_X . The kernel reads and executes instructions from these pages. The kernel maps the other pages with the permissions PTE_R and PTE_W , so that it can read and write the memory in those
pages. The mappings for the guard pages are invalid.

---

### 3.3 Code: creating an address space

- TLB: Table Look-aside Buffer

大部分材质地址空间和页表的代码都在vm.c(kernnel/vm.c)中。最重要的数据结构是pagetable_t，本质上是指向一个RISC-V的根页表页 的指针。而pagetable_t可能是内核页表或者进程页表。最重要的函数是walk，通过虚拟地址找到PTE，以及函数mappages。为新的mappings添加PTE。
kvm开头的函数操作内核页表，uvm操作用户的页表；其余的函数则为以上的函数服务。
> copyout and copyin copy data to and from user virtual addresses provided as system call arguments;
**copyout和copyin是用来复制数据到用户虚拟地址或从用户虚拟地址复制出来，作为系统调用的参数。**

它们都在vm.c中因为需要显示地转换它们的地址来找到对应的物理内存。

在boot sequence启动过程中，main调用kvminit来创建内核页表。这个调用发生在xv6开启RISC-V分页硬件之前，因此地址会直接映射到物理内存。Kvminit首先分配一个物理页来储存根页表。然后调用kvmmap来添加内核需要的转换(即PTE)。
>The translations include the kernel’s instructions and data, physical memory up to PHYSTOP , and memory ranges which are actually devices
>这些转换包含内核指令和内核数据，到PHYSTOP的物理内存，以及设备相关。

kvmmap调用mappages，添加VA到PA的映射到页表中。分别为虚拟地址添加映射，以页为间隔。对于每个需要映射的VA，mappages调用walk来找到该地址的PTE。然后初始化该PTE来存储相应的PPN，以及需要的标志位(PTE_W,PTE_X,PTE_R)，PTE_V使其生效。

当walk为某个虚拟地址查询PTE时，会模仿RISC-V的分页硬件。walk将会通过VA中的高27bit(每9bit对应每级页表的PTE)从上至下walk三级页表从而找到下一级页表页或者最后的页。
若PTE无效则说明需要的页仍未被分配；如果设置了alloc参数，walk则会分配一个新的页表页然后将其物理地址存入PTE。
> It returns the address of the PTE in the lowest layer in the tree (kernel/vm.c:88)
**它会返回页表树最后一层的PTE的地址。**

以上的代码建立在物理内存被直接映射到内核的虚拟地址空间。举个例子，当walk遍历多级页表时，从PTE中拿到下一级页表的PA，然后将它当做VA来提取下一级页表的PTE。

main调用kvminithart(kernel/vm.c:53)来添加内核页表。它将根页表页的PA写入satp。之后物理地址就可以使用内核页表来进行地址翻译。由于内核使用同等映射方式，下一个指令的VA将会映射到正确的物理内存地址。

main调用procinit (kernel/proc.c:26)来为每个进程分配内核栈。它会映射在虚拟地址的由KSTACK产生的每个栈空间，同时也为无效的栈保护页预留了空间。kvmmap将具有映射的PTE到内核页表，然后调用kvminithart重载内核页表到satp，以便硬件能得知新的PTE。

每个RISC-V CPU缓存PTE在TLB(Translation Look-aside Buffer)快表中，当xv6修改页表，它必须告诉CPU将TLB中的相应entries置为无效。如果不这样做，则at some point TCB肯会使用旧的缓存映射，指向一个已经被分配给另一个进程的物理页，结果会造成一个进程写数据到其他进程的内存中。RISC-V有一个指令叫sfence.vma用来刷新当前CPU的TLB。xv6在重载satp寄存器后通过kvminithart执行sfence.vma，在trampoline代码中在返回用户空间前切换到用户页表。

---

### 3.4 Physical memory allocation

内核必须在运行时为页表、用户内存、内核栈以及管道缓存分配和释放物理内存。

xv6使用PHYSTOP和内核末尾之间的物理内存来进行运行时分配。每次分配或释放一个4096字节的页。并维持一个空闲页的链表。分配过程则包括从该链表中移出页，释放过程包括将空闲页加入该链表。

---

### 3.5 Code: Physical memory allocator

分配器在kalloc.c中实现。分配器的数据结构是一个有物理内存中可分配的页所构成的free list。每个空闲页链表的元素都是一个struct run(kernel/kalloc.c)。
那分配器从哪里获得内存来hold这个数据结构呢？
答案是每个空闲页表的run都存储在空闲页的本身，因为没有任何其余的东西存储在那里。

空闲页链表被spin lock保护。
> The list and the lock are wrapped in a struct to make clear that the lock protects the fields in the struct.
这个链表和锁被一个结构体包裹，这个锁就用来保护该结构体的域。

现在暂时忽略锁和acquire和release，章节6将会详细解释锁。
mian调用kinit来初始化allocator. kinit初始化空闲页链表来维持在内核尾和PHYSTOP之间的每一个页。

![](../img/3/Pasted%20image%2020220517110935.png)

xv6通过解析硬件提供的配置信息决定有多少物理内存是可用的。xv6假定机器拥有128MB的RAM。
>kinit calls freerange to add memory to the free list via per-page calls to kfree . 
kinit会调用freerange通过每页的kfree来将内存添加到空闲页链表。

一个PTE只能指向一个在4096字节对齐的物理地址(4096的倍数)，因此freerange使用**PGROUNDUP**来保证它只有在对齐物理地址后才释放。
allocator一开始没有内存，调用kfree将内存交由其管理。

分配器有时为了对地址进行数学运算会将它们当做整数(eg：在freerange遍历所有页)，有时使用地址作为指针来读写内存(eg：操作在页中的run结构体)。地址这样的双重用法的主要原因是实现分配器的代码有许多C的强制类型转换(C type casts)。另一个原因是释放和分配内存会修改内存的类型。
>The function kfree (kernel/kalloc.c:47) begins by setting every byte in the memory being freed to the value 1. 
>函数kfree开始会将内存中被释放的每一个字节设置为1。

这将会导致代码可能会使用被释放后的内存来读取垃圾数据而非旧的有效内容。
> hopefully that will cause such code to break faster.

>Then kfree prepends the page to the free list: it casts pa to a pointer to struct run , records the old start of the free list in r->next , and sets the free list equal to r . kalloc removes and returns the first element in the free list.
然后kfree将会将该页面添加到空闲链表中，将pa强制转换为指向struct run的指针，在r->next记录free list的旧开始，然后将空闲页链表等同于r.kalloc移除和返回free list的第一个元素

---

### 3.6 Process address space

每个进程都有各自的页表，当xv6在进程间切换时，也会切换页表。进程用户内存从VA 0开始然后增长至MAXVA，允许进程在256GB的内存寻址。

当进程向xv6请求更多的用户内存，xv6首先使用kalloc分配物理页。然后将指向新的物理页面的PTEs添加到进程的页表中。xv6为这些PTEs设置PTE_W，PTE_X, PTE_R, PTE_U, 和PTE_V标志位。
大多数进程并不需要使用整个用户地址空间，xv6会将未使用的PTEs的PTE_V标志位清空。
我们看到这里有一些使用页表的不错的示例。

第一，不同的进程页表将用户地址转换成不同的物理地址页，以便每个进程有私有的用户内存。
第二，即便进程的物理内存可以是不连续的，每个进程都会以为自己拥有从零开始的连续内存(虚拟地址)。
第三，内核会将一个储存trampoline代码的物理页映射到用户地址空间的顶部。因此有一个物理页将会出现在所有进程的地址空间。

Fig3.4详细展示了一个运行中进程在xv6的用户内存布局。
stack是单页，写入了exec创建的初始内容。包含命令行参数以及它们的指针的字符串位于栈的最顶部。
>. Just under that are values that allow a program to start at main as if the function main(argc , argv) had just been called.
>往下是main程序的参数

![](../img/3/Pasted%20image%2020220520164512.png)

为了检测用户栈溢出了目前已分配的栈内存，xv6在栈的正下方放置了一个无效的保护页。如果用户的栈溢出然后进程尝试使用栈下方的地址，硬件就会产生一个页错误异常，因为这个映射是无效的。一个现代的操作系统可能会在栈溢出时自动为栈扩容。

---

### 3.7 Code: sbrk

Sbrk是进程收缩或扩充内存的系统调用。该系统调用通过函数`growproc` (kernel/proc.c:239)来实现。`growproc`调用`uvmalloc`或者`uvmdealloc`，取决于n是正数还是负数。
`uvmalloc` (kernel/vm.c:229) 调用`kalloc`来分配物理内存，并且通过`mappages`将PTEs添加到用户页表。
`uvdealloc`调用uvunmap(kernel/vm.c:174)通过`walk`来找到PTEs然后释放其指向的物理内存。

xv6中进程页表不仅仅是告知硬件怎么映射用户的虚拟地址，也是物理内存页被分配给进程的唯一记录。这就是当释放用户内存(在`uvmunmap`中)需要检查用户的页表。

---

### 3.8 Code: exec

Exec是创建用户部分地址空间的系统调用。它会从储存在文件系统中的一个文件初始化用户地址空间。`Exec` (kernel/exec.c:13)使用`namei`(kernel/exec.c:26)打开以path命名的二进制文件，这将会在章节8介绍。然后，它会读取ELF头。xv6使用广泛应用的ELF格式(kernel/elf.h:25)来描述应用。一个ELF二进制文件包含一个ELF头，`struct elfhdr`(kernel/elf.h:6)，跟着一连串的程序节头`struct proghdr`(kernel/elf.h:25)。每个`proghdr`表示必须被加载进内存的程序节；xv6程序只有一个程序节头，但其他的系统可能有不同的指令节和数据节。

[section(节) 和 segment(段)的概念](https://www.cnblogs.com/jiqingwu/p/elf_format_research_01.html)

![](../img/3/Pasted%20image%2020220521105106.png)

第一步是一次快速检查文件可能包含一个ELF binary. 一个ELF binary以四个字节的"魔法数字"0x7F、‘E’、‘L’、‘F’, 或者说`ELF_MAGIC`(kernel/elf.h:3)。如果ELF头拥有正确的魔法数字，exec就会认为该`binary`是正确的。

`Exec`会通过`proc_pagetable`(kernel/exe.c:38)分配一个没有用户空间映射的页表，通过`uvmalloc`(kernel/exe.c)为每个ELF段分配内存，`loadseg`(kernel/exe.c:10)将这些ELF段载入内存。`loadseg`通过`walkaddr`来寻找已被分配的物理内存，然后将ELF段写入，而ELF段是通过`readi`从文件中读取的。

使用`exec`创建的第一个用户程序/init的program header如下所示：
```
# objdump -p _init
user/_init: file format elf64-littleriscv
Program Header:
LOAD off 0x00000000000000b0 vaddr 0x0000000000000000 
                               paddr 0x0000000000000000 align 2 ** 3
         filesz 0x0000000000000840 memsz 0x0000000000000858 flags rwx
STACK off 0x0000000000000000 vaddr 0x0000000000000000
                               paddr 0x0000000000000000 align 2 ** 4
         filesz 0x0000000000000000 memsz 0x0000000000000000 flags rw-
```
program header的`filesz`可能会比`memsz`小，这意味着需要填充0(C的全局变量)而不是从文件中读。对/init而言，filesz是2112字节然后memsz是2136字节，因此`uvmalloc`会分配足够的2136字节的内存，但只从文件/init中读了2112字节。

现在`exec`将会分配和初始化用户栈，xv6中只分配一个stack page。`Exec`将参数字符串一个个复制到栈顶，在`ustack`记录指向它们的指针。然后会在传递给main函数的`argv`列表的末尾放一个空指针。`ustack`开头的三个entries是
>fake return program counter, argc, and argv pointer

`exec`将一个不可访问的page放在stack page下面，从而使得当程序尝试使用大于一页时会出错。这个不可访问的页同时也让`exec`能处理参数太多的情况。在这种情形下，`exec`调用的复制参数到栈的函数`copyout`(kernel/vm.c:355)会通知目标页无法访问，然后返回-1。

在新的内存映像的准备过程中，如果`exec`检测到像无效程序段这样的错误，就会跳转至标签`bad`的位置，释放新的映像，并返回-1。

`Exec`从ELF文件中读取数据到其指定的内存地址。用户或者进程可以将任意地址写到ELF文件中。因此`exec`是有风险的，因为ELF文件中的地址可能无意或有意地指向内核。

---

### 3.9 Real world

像大多数的操作系统一样，xv6使用分页硬件来做内存保护和映射。大多数的操作系统会比xv6更加精巧地利用分页，将分页和分页错误异常结合，这个我们将在章节4讨论。

xv6通过内核使用直接映射来进行简化，在这种假设下物理RAM是在地址0x8000000，也就是内核期望被加载的地址。这在QEMU上能正确工作，但在真正的硬件上这是个馊主意。真实的硬件会将RAM和设备放在不可预测的物理地址，因此在物理地址0x8000000可能并没有xv6期待存放内核的RAM。

更加严谨的内核设计会利用页表将不可预测的硬件物理内存布局转化为可预测的内核虚拟地址布局。

RISC-V同样支持在物理地址层面的保护，但xv6没有使用这一特性。

在拥有更多内存的机器上通过RISC-V的支持来使用超级页可能比较合理。当物理内存小时，小页面会更加合理，从而使得内存分配和页面存入硬盘的操作获得更佳的粒度。举例来说，如果一个程序只用8kB的内存，分配一整个4MB的物理内存超级页就显得浪费。在拥有更大的RAM的机器上使用大页面是合理的，这会减少页表操作的开销。

xv6的内核缺少像malloc一样能为小对象提供内存的分配器，而这就导致内核无法使用需要动态内存分配的精细数据结构。

内存分配是一个长盛不衰的热门话题，基本的问题是如何高效使用有限的内存和预备将来未知的需求。在今天人们更关注速度而非空间效率。此外，一个更加庞杂的内核可能分配不同尺寸的小块，而不是像xv6一样只有4096字节大小的块；一个真正的内核中的内存分配器需要能处理不同大小的分配。如果内核不感知危险，可能会造成瘫痪甚至对内核隔离机制的恶意攻击(比如安全漏洞)。xv6会通过一些检查来避免这些风险。比如，`if(ph.vaddr + ph.memsz < ph.vaddr)`检查和是否溢出了64位整形。当用户在用自定义的地址`ph.vaddr`构建ELF文件时可能会产生这种危险，另外`ph.memsz`过大也会导致和溢出到0x1000，即便看起来是一个有效值。在老版本的xv6中，用户地址空间也包含了内核(但在用户态无法读写)，用户可以选择一个指向内核内存的地址将ELF的数据复制到内核。好在RISC-V的xv6版本中，这不会发生，因为内核有自己的页表，`loadseg`加载入进程的页表，而非内核页表。

对于内核开发者而言非常容易遗漏关键的检查，在现实中，内核因为遗漏一些检查，被用户程序利用从而获得内核特权的情况并不少。xv6并没有进行完全的工作来验证提供给内核的用户级别数据，而这可能会被恶意的用户程序利用来破坏xv6的隔离性。


