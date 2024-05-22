use std::io::Write;

macro_rules! make_checks {
    ($($x:literal),*) => {
        [$(
            |c: u8| {
                let goal = $x as u8;
                let _neg = c - goal;
                let _pos = c + (u8::MAX - goal);
            }
        ),*]
    }
}

#[inline(never)]
fn remove_newline(mut s: &[u8]) -> &[u8] {
    while let [rest @ .., b'\n'] = s {
        s = rest;
    }
    return s;
}

#[inline(never)]
fn check_flag(s: &[u8]) {
    let checks = make_checks!(
        'H', 'T', 'B', '{', 'd', '0', 'n', 't', '_', 
        'p', '4', 'n', '1', 'c', '_', 'c', '4', 't',
        'c', 'h', '_', 't', 'h', 'e', '_', '3', 'r',
        'r', 'o', 'r', '}'
    );
    assert_eq!(s.len(), checks.len());
    for (&chr, check) in s.iter().zip(&checks) {
        check(chr);
    }
}

fn main() {
    std::panic::set_hook(Box::new(|_| ()));
    print!("🤖💬 < Have you got a message for me? > 🗨️ 🤖: ");
    let _ = std::io::stdout().flush();
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf).expect("couldn't read stdin");
    match std::panic::catch_unwind(|| check_flag(remove_newline(buf.as_bytes()))) {
        Ok(_) => println!("😌😌😌 All is well 😌😌😌"),
        Err(_) => println!("😱😱😱 You made me panic! 😱😱😱"),
    }
}
