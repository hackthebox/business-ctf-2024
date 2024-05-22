<img src="../../assets/banner.png" style="zoom: 80%;" align=center />

<img src="../../assets/htb.png" style="zoom: 80%;" align='left' /><font size="6">DontPanic</font>

  13<sup>th</sup> 05 24 / Document No. D24.102.72

  Prepared By: clubby789

  Challenge Author: clubby789

  Difficulty: <font color=green>Easy</font>

  Classification: Official






# Synopsis

Don't Panic is an Easy reversing challenge. Players will reverse a Rust binary using the `catch_unwind` mechanism to check a flag.

## Skills Required
    - Basic decompiler usage
## Skills Learned
    - Rust reversing fundamentals
    - Binary automation scripting

# Solution

Running the binary, we're prompted for some input. Entering anything will give us an error message.

```
🤖💬 < Have you got a message for me? > 🗨️ 🤖: Hello
😱😱😱 You made me panic! 😱😱😱
```

We'll open it in a decmpiler.

## Analysis

We can see from strings in the binary that this is a Rust binary. Luckily, it is not stripped so we have a lot of information about the binary. We'll navigate to `src::main` to start.

Note: Rust adds a hash to the end of function names to differentiate functions with the same name, e.g. `src::main::hf9bc229851763ab9` - these will be emitted here.

```c
void src::main::hf9bc229851763ab9()
    void* r15
    void* var_10 = r15
    std::panicking::set_hook::h5903f2b6823764d7(1, &data_58220)
    void** const var_60 = &data_58250
    int64_t var_58 = 1
    char const* const var_50 = &data_47000
    int128_t var_48 = zx.o(0)
    std::io::stdio::_print::h5c2f653c9c3347e5(&var_60)
```

First, `std::panicking::set_hook` is called. This replaces Rust's default 'panic hook'. Panicking is a mechanism like exceptions - a fatal error message is thrown (the default panic hook prints out the message), then the program 'unwinds', jumping back up through the function call stack to run destructors.

If we follow the second argument, we reach a function that returns without doing anything else - this essentially disables printing panic messages.

## Printing

For the sake of increasing readability, we'll reverse the argument passed to the `_print` function. This is an undocumented function used internally to print out some data with formatting - we can view its signature [here](https://stdrs.dev/nightly/x86_64-unknown-linux-gnu/std/io/stdio/fn._print.html).

Rust format strings look like `Hello, {name}!` - this is represented by the [`Arguments`](https://stdrs.dev/nightly/x86_64-unknown-linux-gnu/std/fmt/struct.Arguments.html) struct.

```rust
pub struct Arguments<'a> {
    pieces: &'a [&'static str],
    fmt: Option<&'a [Placeholder]>,
    args: &'a [Argument<'a>],
}
```

`pieces` are the static string parts (in this example, `["Hello, ", "!"]`). `fmt` contains the information of the formatting placeholders (i.e. `[{name}]`) and `args` contains any arguments passed to be formatted.

A slice in Rust (`&[Type]`) is represented as a pointer followed by a size. An optional slice (`Option<&[T]>`) is represented the same, but with the pointer as NULL to represent the absence. We'll add this type to our decompiler like so:

```c
struct slice
{
    void* ptr;
    uint64_t size;
};

struct Arguments
{
    struct slice pieces;
    struct slice fmt;
    struct slice args;
};
```

This allows our decompilation to be updated to
```c
struct Arguments msg
msg.pieces.ptr = &data_58250
msg.pieces.size = 1
msg.fmt.ptr = &data_47000
msg.fmt.size = 0
msg.args.ptr = 0
std::io::stdio::_print::h5c2f653c9c3347e5(&msg)
```
`data_58250` contains a pointer to the message printed out.

Moving on to input reading:

```c
struct String buf
buf.capacity = 0
buf.ptr = 1
buf.length = 0
void* stdin = std::io::stdio::stdin::h8c974ef3a60924c0()
int64_t rax_1
int64_t rdx
rax_1, rdx = std::io::stdio::Stdin::read_line::hdb4e3d7cbacc71a9(&stdin, &buf)
if (rax_1 != 0) {
    msg.pieces.ptr = rdx
    core::result::unwrap_failed::h5119205a73b72b0d(&data_47006[0x3a], 0x13)
    noreturn
}
char* new_ptr
uint64_t new_end
new_ptr, new_end = src::remove_newline::h49daf0023bf5b77c(ptr: buf.ptr, sz: buf.length)
src::check_flag::h397d174e03dc8c74(new_ptr, new_end)
```

We initialize an empty `String`:

```c
struct String
{
    uint64_t capacity;
    char* ptr;
    uint64_t length;
};
```

A `ptr` of 1 is used rather than `NULL` for optimization reasons. `read_line` is called to read a line from the stdin instance into the buffer, with a panic if this fails.

The result is then processed with `remove_newline`:

```c
int64_t src::remove_newline::h49daf0023bf5b77c(char* ptr, uint64_t sz)

uint64_t end
do {
    end = sz
    uint64_t sz_1 = sz
    sz -= 1
    if (sz_1 u< 1) {
        break
    }
} while (ptr[end - 1] == '\n')
return ptr, end
```
We iterate backwards over the string to remove any trailing newlines, then return the pointer and new size.

### Flag Checking

We'll now analyze `check_flag`.

```c
int64_t src::check_flag::h397d174e03dc8c74(char* flag, uint64_t sz)

void (* functions[0x1f])(char arg1)
functions[0] = core::ops::function::FnOnce::call_once::h32497efb348ffe3c
functions[1] = core::ops::function::FnOnce::call_once::h827ece763c8c7e2e
// < .. SNIP .. >
functions[0x1d] = core::ops::function::FnOnce::call_once::h4aee5a63c69b281c
functions[0x1e] = core::ops::function::FnOnce::call_once::he29dc24b9b003076
uint64_t sz_1 = sz
int64_t var_140 = 0x1f
if (sz != 0x1f) {
    int64_t var_40 = 0
    core::panicking::assert_failed::hb9915114bebb1f93(&sz_1, &var_140, &var_40)
    noreturn
}
int64_t result = 0
int64_t i
do {
    i = result + 1
    functions[result](flag[result])
    result = i
} while (i != 0x1f)
return result
```

A large array of function pointers is initialized. We then assert that the flag size is equal to `0x1f`, otherwise we panic. Here we can observe something interesting - as seen earlier, the binary does not panic, but prints out a message and returns normally. This may indicate that the panic is being caught.

### `catch_unwind`

[`catch_unwind`](https://doc.rust-lang.org/std/panic/fn.catch_unwind.html) allows an in-progress panic to be caught and halted once it reaches the point that `catch_unwind` was called. This can be useful for, e.g. web services, where a failure in a request should not cause the entire process to terminate. Immediately after `main`, there are a large chunk of bytes which a decompiler may or may not automatically disassemble.

Manually disassembling these into functions reveals some call to `_Unwind_Resume`. This is a function also used by C++ exceptions to continue unwinding. However, one function calls `std::panicking::try::cleanup::h9d12b4e901152846` and prints out a message which we can verify is the failure message from earlier.

We can determine then that the binary catches panics and uses them to indicate failure - not panicking in our checks means the flag is correct.

Returning to the `check_flag` function, we can see that each function pointer is called on each character of our input in turn. If we check the first one:

```c
void core::ops::function::FnOnce::call_once::h3dae80a6281f81f5(char arg1)
    if (arg1 u< 0x48) {
        core::panicking::panic::h8ddd58dc57c2dc00("attempt to subtract with overflow")
        noreturn
    }
    if (arg1 != 0x48) {
        core::panicking::panic::h8ddd58dc57c2dc00("attempt to add with overflow")
        noreturn
    }
```
We can see that it checks if a value is below or not equal to a constant - in this case, 'H'.

## Solving

We can now solve by extracting the constants from these checks. By checking each one in turn, we can recover the flag.