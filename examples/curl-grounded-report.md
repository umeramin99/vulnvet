# Question about integer overflow potential in dynbuf growth (curl 8.4.0)

> A deliberately *well-grounded* report, for contrast with the fabricated
> example alongside it. Every citation here is real: the functions, the
> file, the line numbers and the quoted code all exist in curl 8.4.0. The
> report may or may not describe a real bug — vulnvet's job is to show you
> that the reporter is describing code that actually exists, so the
> question is worth your time.
>
> ```console
> $ git clone --depth 1 --branch curl-8_4_0 https://github.com/curl/curl
> $ vulnvet curl-grounded-report.md --repo curl --rev 8.4.0
> ```

## Summary

While reading curl 8.4.0 I want to check my understanding of the buffer
growth loop in `dyn_nappend()` in `lib/dynbuf.c`. I am **not** claiming a
vulnerability — I could not construct one — but I would like to confirm
the reasoning is sound before dropping it.

## Details

`Curl_dyn_addn()` is the public entry point and forwards to the static
helper `dyn_nappend()`, which starts at lib/dynbuf.c:67. The size
computation is at lib/dynbuf.c:70.

The relevant code from lib/dynbuf.c:

```c
  size_t indx = s->leng;
  size_t a = s->allc;
  size_t fit = len + indx + 1; /* new string + old string + zero byte */
```

`fit` is computed before any bounds test, so if a caller could reach this
with `len` close to `SIZE_MAX` the addition would wrap and produce a small
`fit` value, which would then pass the `fit > s->toobig` check.

My reading is that this is **not** reachable in practice: every caller
bounds `len` by an already-allocated buffer, and `s->toobig` is set at
init. I could not find a call path that passes an attacker-chosen `len`
larger than an existing allocation. I am reporting it only in case there
is a path I missed — please close this if the invariant is documented
somewhere I did not look.

## Environment

Reproduced against 8.4.0. Also read the same code on 8.3.0 and the logic
appears unchanged.
