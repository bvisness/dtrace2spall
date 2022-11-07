# dtrace2spall

Converts DTrace profiles to the Spall format.

[Spall](https://gravitymoth.com/spall/) is an extremely fast profiler by Colin Davidson. For optimal file size and load times, Spall has a proprietary binary format. This tool produces files in that format.

This tool is designed to work with DTrace's [`profile`](https://illumos.org/books/dtrace/chp-profile.html#chp-profile) and [`ustack`](https://illumos.org/books/dtrace/chp-user.html#chp-user-4) providers. See below for examples.

## Installing

[Go 1.19](https://go.dev/) or higher is required. Make sure that `$GOBIN` or `$HOME/go/bin` is on your PATH.

```
go install github.com/bvisness/dtrace2spall@latest
```

## Quick Start

```bash
# Run DTrace and save to profile.dtrace
dtrace -n 'profile-997 /pid == $target/ { @[timestamp, pid, tid, ustack(100)] = count(); }' \
    -x ustackframes=100 \
    -o profile.dtrace \
    -x aggsortkey -x aggsortkeypos=0 \
    -c <path to my program>
# Convert to Spall and save to profile.spall
cat profile.dtrace | dtrace2spall --freq 997 -o profile.spall --fields=-,pid,tid
```

## Detailed Usage

```
Usage:
  dtrace2spall [flags]

Flags:
      --fields strings   An array of fields preceding each stack. Valid fields: pid, tid. Any unrecognized fields will be ignored (consider using "-" for any such fields).
  -f, --freq int         The frequency of profile sampling, in Hz. (default 1000)
  -h, --help             help for dtrace2spall
  -o, --out string       The file to write the results to. Use "-" for stdout.
      --passthrough      Pass the input data through to stdout, making this tool invisible to pipelines. Requires --out.
```

### Simple profiling

The simplest use of DTrace for user-level profiling is with the [`profile`](https://illumos.org/books/dtrace/chp-profile.html#chp-profile) and [`ustack`](https://illumos.org/books/dtrace/chp-user.html#chp-user-4) providers. The DTrace program and invocation might look like:

```
profile-997
/pid == $target/
{
    @[ustack(100)] = count();
}
```

```
dtrace -n 'profile-997 /pid == $target/ { @[ustack(100)] = count(); }' \
    -x ustackframes=100 \
    -o profile.dtrace \
    -c <path to my program>
```

This will sample program execution at a rate of 997Hz and store the results in `profile.dtrace`. This file can then be converted to Spall:

```
cat profile.dtrace | dtrace2spall --freq 997 -o profile.spall
```

Note that DTrace does not sort the results by time when used this way.

### Profiling with fields (incl. multiprocess or multithreaded code)

The above DTrace program can be expanded to capture process and thread information:

```
profile-997
/pid == $target/
{
    @[pid, tid, ustack(100)] = count();
}
```

```
dtrace -n 'profile-997 /pid == $target/ { @[pid, tid, ustack(100)] = count(); }' \
    -x ustackframes=100 \
    -o profile.dtrace \
    -c <path to my program>
```

When converting to Spall, pass the extra fields in the `--fields` flag:

```
cat profile.dtrace | dtrace2spall --freq 997 -o profile.spall --fields=pid,tid
```

### Preserving order of events

You may notice that DTrace does not preserve the order of events when used this way. By including a `timestamp` field in the results and sorting by it, we can get around this.

```
profile-997
/pid == $target/
{
    @[timestamp, pid, tid, ustack(100)] = count();
}
```

```
dtrace -n 'profile-997 /pid == $target/ { @[timestamp, pid, tid, ustack(100)] = count(); }' \
    -x ustackframes=100 \
    -o profile.dtrace \
    -x aggsortkey -x aggsortkeypos=0 \
    -c <path to my program>
```

When converting to spall, we can use `-` for the timestamp field since it is not recognized by `dtrace2spall`:

```
cat profile.dtrace | dtrace2spall --freq 997 -o profile.spall --fields=-,pid,tid
```

## FAQ

- **How can I profile at a different rate?**

    There may be other profile frequencies available on your system, e.g. `profile-1000` or `profile-4999`. To list them, run:

    ```
    dtrace -l | grep profile
    ```

- **I am getting warnings about "aggregation drops".**

    DTrace by default has very small buffers for aggregating data. You can expand them with the `aggsize` variable, e.g. `-x aggsize=10m`.
