// SPDX-License-Identifier: Apache-2.0
// Nodus CUDA readiness probe: verify visible device count, UUIDs and device memory contents.
#include <cuda.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PROBE_BYTES (1 << 20)

static int fail(const char *step, int dev, CUresult r) {
	const char *name = NULL;
	cuGetErrorName(r, &name);
	fprintf(stderr, "probe: %s failed on device %d: %s\n", step, dev, name ? name : "unknown error");
	return 1;
}

static int check(int dev, unsigned char *host) {
	CUdevice d;
	CUcontext ctx;
	CUdeviceptr mem;
	CUresult r;
	if ((r = cuDeviceGet(&d, dev)) != CUDA_SUCCESS) return fail("cuDeviceGet", dev, r);
	if ((r = cuCtxCreate(&ctx, 0, d)) != CUDA_SUCCESS) return fail("cuCtxCreate", dev, r);
	int bad = 0;
 const char *expected = getenv("NODUS_PROBE_UUIDS");
 if (expected && *expected) {
  CUuuid id;
  if ((r = cuDeviceGetUuid(&id, d)) != CUDA_SUCCESS) { cuCtxDestroy(ctx); return fail("cuDeviceGetUuid", dev, r); }
  char actual[41];
  snprintf(actual,sizeof(actual),"GPU-%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
   (unsigned char)id.bytes[0],(unsigned char)id.bytes[1],(unsigned char)id.bytes[2],(unsigned char)id.bytes[3],
   (unsigned char)id.bytes[4],(unsigned char)id.bytes[5],(unsigned char)id.bytes[6],(unsigned char)id.bytes[7],
   (unsigned char)id.bytes[8],(unsigned char)id.bytes[9],(unsigned char)id.bytes[10],(unsigned char)id.bytes[11],
   (unsigned char)id.bytes[12],(unsigned char)id.bytes[13],(unsigned char)id.bytes[14],(unsigned char)id.bytes[15]);
  const char *found = strstr(expected,actual);
  if (!found || (found!=expected && found[-1]!=',') || (found[40]!='\0' && found[40]!=',')) {
   fprintf(stderr,"probe: unexpected physical GPU identity on device %d\n",dev);
   cuCtxDestroy(ctx); return 1;
  }
 }
 if ((r = cuMemAlloc(&mem, PROBE_BYTES)) != CUDA_SUCCESS) {
		bad = fail("cuMemAlloc", dev, r);
	} else {
		if ((r = cuMemsetD8(mem, 0xA5, PROBE_BYTES)) != CUDA_SUCCESS) bad = fail("cuMemsetD8", dev, r);
		else if ((r = cuMemcpyDtoH(host, mem, PROBE_BYTES)) != CUDA_SUCCESS) bad = fail("cuMemcpyDtoH", dev, r);
		else {
			for (int i = 0; i < PROBE_BYTES; i++) {
				if (host[i] != 0xA5) {
					fprintf(stderr, "probe: device %d returned wrong memory contents\n", dev);
					bad = 1;
					break;
				}
			}
		}
		cuMemFree(mem);
	}
	cuCtxDestroy(ctx);
	return bad;
}

int main(void) {
	CUresult r;
	int n = 0;
	if ((r = cuInit(0)) != CUDA_SUCCESS) return fail("cuInit", -1, r);
	if ((r = cuDeviceGetCount(&n)) != CUDA_SUCCESS) return fail("cuDeviceGetCount", -1, r);
	const char *want = getenv("NODUS_PROBE_GPUS");
	if (want && *want && atoi(want) != n) {
		fprintf(stderr, "probe: %d devices visible, want %s\n", n, want);
		return 1;
	}
	unsigned char *host = malloc(PROBE_BYTES);
	if (!host) {
		fprintf(stderr, "probe: out of host memory\n");
		return 1;
	}
	int bad = 0;
	for (int dev = 0; dev < n; dev++) bad |= check(dev, host);
	free(host);
	if (!bad) printf("probe: %d devices ready\n", n);
	return bad;
}
