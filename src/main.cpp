#include "capture.h"
#include "checksum.h"
#include "tcp.h"
#include "tls.h"
#include "trie.h"
#include "utils.h"

#define IP_LEVEL_OFFSET 14
#define TCP_LEVEL_OFFSET 0x22

int main() {
  int manage_tcp_stream_nums = 60000;
  init_hash();
  init_tcp(manage_tcp_stream_nums);
  register_tcp_callbk(process_tls);

  if (caputure_packet_from_file(
          "/home/chuancey/workspace/Protocol_Restoration/doc/tls1.2.pcap",
          process_tcp) == -1)
    return -1;
  release_pcap_resource();
  // release_trie_resource();

  return 0;
}