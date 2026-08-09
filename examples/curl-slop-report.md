# Buffer overflow in curl's HTTP/3 priority frame handling (WebSocket upgrade path)

> This example reconstructs the *shape* of the infamous AI-fabricated report
> against curl (HackerOne #2199174, October 2023) - the report that helped
> push curl's maintainers toward ending their bug bounty. The wording is
> ours; the fabricated technical claims mirror the original. Run it against
> a curl checkout:
>
> ```console
> $ git clone --depth 1 --branch curl-8_4_0 https://github.com/curl/curl
> $ vulnvet curl-slop-report.md --repo curl --rev 8.4.0
> ```

## Summary

A heap buffer overflow exists in curl's HTTP/3 implementation. The function
`ngtcp2_http3_handle_priority_frame()` in `lib/vquic/ngtcp2.c` does not
validate the length of an incoming PRIORITY_UPDATE frame before copying it
into a fixed-size stack buffer, leading to memory corruption and potential
remote code execution. The issue affects versions 8.1.0 through 8.4.0 and
is reachable whenever HTTP/3 is negotiated.

## Technical details

When a server sends a crafted priority frame, `nghttp3_conn_read_stream()`
dispatches to the vulnerable handler. The overflow occurs at
`lib/vquic/ngtcp2.c:1042`, where the frame payload is copied without a
bounds check.

The vulnerable code in lib/vquic/ngtcp2.c looks like this:

```c
static int ngtcp2_http3_handle_priority_frame(struct Curl_cfilter *cf,
                                              struct stream_ctx *stream,
                                              const uint8_t *frame)
{
  uint8_t prio_buf[64];
  size_t frame_len = ngtcp2_get_frame_length(frame);
  memcpy(prio_buf, frame + PRIORITY_HDR_LEN, frame_len);
  return ngtcp2_apply_priority_update(cf, stream, prio_buf);
}
```

## Crash report

```
==41414==ERROR: AddressSanitizer: stack-buffer-overflow
    #0 0x55e3f1a2b4c1 in ngtcp2_http3_handle_priority_frame /src/curl/lib/vquic/ngtcp2.c:1042
    #1 0x55e3f1a2a911 in cf_ngtcp2_recv /src/curl/lib/vquic/ngtcp2.c:2007
    #2 0x55e3f19c88a2 in Curl_conn_recv /src/curl/lib/cf-socket.c:912
```

## Impact

Remote attackers can execute arbitrary code on any client using curl with
HTTP/3. Given curl's install base this is a critical severity issue.
