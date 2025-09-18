/**********************************************************************
 * file:  sr_router.c
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface)
{
    printf("===> Packet received on interface: %s, length: %d\n", interface, len);

    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    if (len < sizeof(struct sr_ethernet_hdr)) {
        fprintf(stderr, "Error: Packet too short for Ethernet header\n");
        return;
    }

    struct sr_ethernet_hdr* ethernet_hdr = (struct sr_ethernet_hdr*) packet;
    uint16_t eth_type = ntohs(ethernet_hdr->ether_type);

    //printf("    Ethertype: 0x%04x\n", eth_type);

    if (eth_type == ethertype_ip) {
        printf("  Handling IP packet\n");
        handle_ip_packet(sr, packet, len, interface);
    } else if (eth_type == ethertype_arp) {
        printf("   Handling ARP packet\n");
        handle_arp_packet(sr, packet, len, interface);
    } else {
       // fprintf(stderr, "Error: Unknown Ethertype 0x%04x\n", eth_type);
    }
}


/* end sr_handlepacket */

void handle_ip_packet(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface)
{
    printf(" Entered handle_ip_packet()\n"); 
    //parsing code:
    // extract header, validate checksum
  struct sr_ethernet_hdr * ethernet_hdr = (struct sr_ethernet_hdr*) packet;
  


 // packet is a row of bytes: [ethernet header ... ip header ... payload]
struct sr_ip_hdr * ip_header = (struct sr_ip_hdr * )(packet + sizeof(struct sr_ethernet_hdr));
//check that it meets minimum length 

if (len < sizeof(struct sr_ethernet_hdr) + ntohs(ip_header->ip_len)) {
    fprintf(stderr, "ERROR dropped: ip length > actual length \n");
    return;
}

//validating the checksum:
uint16_t curr_checksum = ip_header->ip_sum;
//set the checksum equal to zero to recompute the checksum
ip_header->ip_sum = 0;
//recalculate checksum
uint16_t recomputed_checksum = cksum((void*)ip_header, sizeof(struct sr_ip_hdr));
//compare to see if the checksums are the same. 
if (curr_checksum != recomputed_checksum) {
  //handle appropriately. 
    fprintf(stderr, "Invalid ip header checksum: dropping packet.\n");
    return;

}
//resotre the checksum becuase now we know theyre the same, to continue processing. 
ip_header->ip_sum = curr_checksum;

//now we determine if its destined for one of our interfaces

int for_curr_router = 0;
struct sr_if* router_interface = sr->if_list;
while (router_interface != NULL) {
    if (ip_header->ip_dst == router_interface->ip) {
        for_curr_router = 1;
        break;
    }
    router_interface = router_interface->next;
}
//now we can handle the logic if its for the current router:
if (for_curr_router) {
      //drop if its one of our interfaces
    struct sr_if* iface = sr->if_list;
    while (iface) {
        //loop check:
        if (ip_header->ip_src == iface->ip) {

            printf("Loop detected: packet dropped\n");
            return;
        }

        iface = iface->next;
    }
  //if its for one of our interfaces, check that its an ICMP echo request( type 8)

  if (ip_header->ip_p == ip_protocol_icmp) {
    //order in memory: eth header .. ip header .. icmp header .. icmp payload
    struct sr_icmp_hdr * icmp_header = (struct sr_icmp_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
      printf("[ICMP DEBUG] Type: %d, Code: %d\n", icmp_header->icmp_type, icmp_header->icmp_code);

    if(icmp_header->icmp_type == 8){ //then its an icmp echo request
      //send echo reply using helper function to send echo reply. 

      icmp_echo_reply(sr, packet, len, interface);


    } else{
      //drop the packet 
      return;
    }

  } else { //not an echo request so we send port unreachable = type 3 code 3
    printf("Not an echo request: sending port unreachable\n");
    send_icmp_error(sr, packet, len, 3, 3, interface);
  }
} else { //now we consider that its not for this router, so we handle forwarding
  
  //handle case if ttl will expire at this router 
  if(ip_header->ip_ttl <= 1){  
    printf("error: TTL expired, sending icmp time exceeded\n"); 
    send_icmp_error(sr, packet, len, 11, 0, interface);
    return;
  }
  //decrease TTL  and then recmopute checksum 
  ip_header->ip_ttl--;
  ip_header->ip_sum = 0;
  ip_header->ip_sum = cksum((void*)ip_header, sizeof(struct sr_ip_hdr));
  
  
  //now use routing table to find the next hop using helper function
  struct sr_rt* matching_rt = find_longest_prefix_match(sr, ip_header->ip_dst);
  if (!matching_rt) {
      printf("Error: no route found to host, sending icmp dest unreachable \n"); 
      send_icmp_error(sr, packet, len, 3, 0, interface);
      return;

  }
  /*

  // loop detection for debugging/testing
    if (strcmp(interface, matching_rt->interface) == 0) {
        printf(" Loop found: incoming and outgoing interface are the same \n");
        return;
    }

    */
  //if this address is within the same LAN, can route directly to it, else need to route to a router outside of the network using gateway
  uint32_t next_hop_ip;
  if (matching_rt->gw.s_addr != 0) {
    next_hop_ip = matching_rt->gw.s_addr; //send to gateway
  } else {
      next_hop_ip = ip_header->ip_dst; //send directly to destination
  }
    //printf("[Forwarding] Forwarding packet...\n");
   //printf("    Source IP: %s\n", ip_to_string(ip_header->ip_src));
   // printf("    Dest IP: %s\n", ip_to_string(ip_header->ip_dst));
    //printf("    Outgoing interface: %s\n", matching_rt->interface);
    //printf("    Next hop IP: %s\n", ip_to_string(next_hop_ip));
    


   //get outgoin interface
    struct sr_if* out_iface = sr_get_interface(sr, matching_rt->interface);
    if (!out_iface) {
        printf("Error: could not find outgoing interface %s\n", matching_rt->interface);
        return;
    }


  //now that we have the next hop, check the cache and handle cases. 
  struct sr_arpentry* cache_entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
  
  
  if (cache_entry) {
 
    //update source and dest mac addresses because we have access to them
    memcpy(ethernet_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
    memcpy(ethernet_hdr->ether_dhost, cache_entry->mac, ETHER_ADDR_LEN);

    //send packet
    //prevet forwarding a packet to ourselves  --  loop prevention
          struct sr_if* temp_iface = sr->if_list;
      while (temp_iface) {
          if (ip_header->ip_dst == temp_iface->ip) {
            //drop packet if the destiation ip is one of our ips, to avoid loop
              return;
          }
          temp_iface = temp_iface->next;
      }
      //end fix 
    sr_send_packet(sr, packet, len, matching_rt->interface);

    //free the cache entry tha was mallocd by sr arpcache lookup 
    free(cache_entry);
    return; 
  } else {
      //if we dont know the mac yet, we queue packet and trigger arp request 
      struct sr_if* out_interface = sr_get_interface(sr, matching_rt->interface);
      if (!out_interface) {
        fprintf(stderr, "Error: could not find outgoing interface\n");
        return;
      }

      sr_arpcache_queuereq(&sr->cache, next_hop_ip, packet, len, out_interface->name);
      return;
  }

}





}

void handle_arp_packet(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface)
{
  printf("Entered handle_arp_packet()\n");


  //get the ARP header from memory -- past eth header
  struct sr_arp_hdr* arp_header = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

  //check, handle arp request 
  if (ntohs(arp_header->ar_op) == arp_op_request) {

    //go through the router interfaces, see if it belongs to us 
    struct sr_if* curr_router_interface = sr->if_list;
      while (curr_router_interface) {
            if (arp_header->ar_tip == curr_router_interface->ip) {
            // this means the arp request is for this router so we need to send a reply
            // total length = eth + arp headers
              unsigned int arp_reply_packet_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);

              //allocate space for the arp reply, handle error with malloc accordingly.
              uint8_t* arp_reply_packet = (uint8_t*)malloc(arp_reply_packet_len);
              if (!arp_reply_packet) {
                    fprintf(stderr, "Error: malloc failed when building arp reply\n");
                    return;
              }

                //fill out eth header for the arp reply
                struct sr_ethernet_hdr* ethernet_header_reply = (struct sr_ethernet_hdr*)arp_reply_packet;
                memcpy(ethernet_header_reply->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN); // dest = sender
                memcpy(ethernet_header_reply->ether_shost, curr_router_interface->addr, ETHER_ADDR_LEN); // source = our mac
                ethernet_header_reply->ether_type = htons(ethertype_arp);

                //fill arp header for the reply
                struct sr_arp_hdr* arp_header_reply = (struct sr_arp_hdr*)(arp_reply_packet + sizeof(struct sr_ethernet_hdr));
                arp_header_reply->ar_hrd = htons(arp_hrd_ethernet);

              arp_header_reply->ar_pro = htons(ethertype_ip);
              arp_header_reply->ar_hln = ETHER_ADDR_LEN;
               arp_header_reply->ar_pln = 4;
               arp_header_reply->ar_op  = htons(arp_op_reply); // arp reply, so set ar_op
              memcpy(arp_header_reply->ar_sha, curr_router_interface->addr, ETHER_ADDR_LEN); // the sender mac is our mac,
              arp_header_reply->ar_sip = curr_router_interface->ip;                          // sender is current ip
              memcpy(arp_header_reply->ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN); // target mac, target ip = original sender, og ip
              arp_header_reply->ar_tip = arp_header->ar_sip;                       
              //send out the the reply out on the same iface the request came in
              sr_send_packet(sr, arp_reply_packet, arp_reply_packet_len, curr_router_interface->name);
              free(arp_reply_packet);
              return;
            }
            curr_router_interface = curr_router_interface->next;
        }

    } 
    //handle arp reply 
    else if (ntohs(arp_header->ar_op) == arp_op_reply) {
        // insert to our cache
        struct sr_arpreq *arp_request_in_queue = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, arp_header->ar_sip);

        //if packets are in teh queue, send them now that we resolved 
        if (arp_request_in_queue) {
            struct sr_packet *packet_in_queue = arp_request_in_queue->packets;
            while (packet_in_queue) {

                //update eth headers now that wehave mac addr 
                struct sr_ethernet_hdr *ethernet_header_to_send = (struct sr_ethernet_hdr *)packet_in_queue->buf;
                memcpy(ethernet_header_to_send->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN); //dest is resolved mac
                memcpy(ethernet_header_to_send->ether_shost, sr_get_interface(sr, packet_in_queue->iface)->addr, ETHER_ADDR_LEN); //source is our iface mac
                //send the packet now
                sr_send_packet(sr, packet_in_queue->buf, packet_in_queue->len, packet_in_queue->iface);
                packet_in_queue = packet_in_queue->next;
            }

            //once packets have been sent we can remove arp req
            sr_arpreq_destroy(&sr->cache, arp_request_in_queue);
        }

        // debug statement to show cache insertion -- kept for ta review purposes if needed alongside writeup
            /*
            printf("inserted %s → %02x:%02x:%02x:%02x:%02x:%02x into cache\n",
                inet_ntoa(*(struct in_addr*)&arp_header->ar_sip),
                arp_header->ar_sha[0], arp_header->ar_sha[1], arp_header->ar_sha[2],
                arp_header->ar_sha[3], arp_header->ar_sha[4], arp_header->ar_sha[5]);
            */
        return;
    }
}




/* Add any additional helper methods here & don't forget to also declare
them in sr_router.h.

If you use any of these methods in sr_arpcache.c, you must also forward declare
them in sr_arpcache.h to avoid circular dependencies. Since sr_router
already imports sr_arpcache.h, sr_arpcache cannot import sr_router.h -KM */




//helper function for sending icmp echo reply:

void icmp_echo_reply(struct sr_instance* sr, uint8_t* packet, unsigned int len, const char* interface)
{

  uint8_t * icmp_reply = (uint8_t*)malloc(len);
  if(icmp_reply == NULL){
    printf("      not enough memory to create icmp reply packet\n");
    return;
  }
  
  //copy echo request for ease, change source/destination, type, 
  memcpy(icmp_reply, packet, len);
  //create pointers to the parts of the packet
  struct sr_ethernet_hdr * icmp_reply_eth_header = (struct sr_ethernet_hdr * )icmp_reply;
  struct sr_ip_hdr * icmp_reply_ip_header = (struct sr_ip_hdr * )(icmp_reply + sizeof(struct sr_ethernet_hdr));
  struct sr_icmp_hdr* icmp_reply_icmp_header = (struct sr_icmp_hdr * )(icmp_reply + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));


  unsigned int icmp_len = len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr);

  icmp_reply_icmp_header->icmp_type = 0;
  icmp_reply_icmp_header->icmp_code = 0;
  icmp_reply_icmp_header->icmp_sum = 0;
  icmp_reply_icmp_header->icmp_sum = cksum(icmp_reply_icmp_header, icmp_len);

  //switch source and destination of mac and ip addresses (since its for us, we have all the information about the sender/receiver necessary)
uint8_t mac_placeholder[ETHER_ADDR_LEN];
memcpy(mac_placeholder, icmp_reply_eth_header->ether_dhost, ETHER_ADDR_LEN);
memcpy(icmp_reply_eth_header->ether_dhost, icmp_reply_eth_header->ether_shost, ETHER_ADDR_LEN);
memcpy(icmp_reply_eth_header->ether_shost, mac_placeholder, ETHER_ADDR_LEN);


uint32_t ip_placeholder = icmp_reply_ip_header->ip_src;
icmp_reply_ip_header->ip_src = icmp_reply_ip_header->ip_dst;
icmp_reply_ip_header->ip_dst = ip_placeholder;

icmp_reply_ip_header->ip_sum = 0;
icmp_reply_ip_header->ip_sum = cksum(icmp_reply_ip_header, sizeof(struct sr_ip_hdr));


struct sr_rt* rt = find_longest_prefix_match(sr, icmp_reply_ip_header->ip_dst);
if (!rt) {
    printf(" ERROR no route to host: cannot send echo reply.\n");
    free(icmp_reply);
    return;
}

struct sr_if* out_iface = sr_get_interface(sr, rt->interface);
if (!out_iface) {
    printf("ERROR: outgoig interface not found.\n");
    free(icmp_reply);
    return;
}
//
uint32_t next_hop_ip;
if (rt->gw.s_addr != 0) {
    next_hop_ip = rt->gw.s_addr;
} else {
    next_hop_ip = icmp_reply_ip_header->ip_dst;
}
struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
if (entry) {
    //set the mac addresses
    memcpy(icmp_reply_eth_header->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
    memcpy(icmp_reply_eth_header->ether_dhost, entry->mac, ETHER_ADDR_LEN);
  //then send the packet
    sr_send_packet(sr, icmp_reply, len, out_iface->name);
    free(entry);
    free(icmp_reply);
} else {
    //queue/tripgger arp req
    sr_arpcache_queuereq(&sr->cache, next_hop_ip, icmp_reply, len, out_iface->name);
}
}



struct sr_rt* find_longest_prefix_match(struct sr_instance* sr, uint32_t dest_ip) {
    struct sr_rt* curr_ptr = sr->routing_table;
    struct sr_rt* longest_prefix_match = NULL;
    
    uint32_t longest_mask = 0;

    while (curr_ptr) {
      //check if applyign the mask to dest_ip matches applying that same mask to the current ip
      uint32_t mask = curr_ptr->mask.s_addr;
      uint32_t route_entry_network = curr_ptr->dest.s_addr & mask;
      uint32_t dest_network = dest_ip & mask;
      if (route_entry_network == dest_network) { 
        //if its the longest one we have found so far then keep track of it,
        //longest subnet prefix-->find the longest mask out of the matching routes
        uint32_t curr_mask_ntohl = ntohl(curr_ptr->mask.s_addr);
        if (curr_mask_ntohl > longest_mask) {
          longest_mask = curr_mask_ntohl;
          longest_prefix_match = curr_ptr;
        }
      }
        curr_ptr = curr_ptr->next;
    }
    return longest_prefix_match;
}






void send_icmp_error(struct sr_instance *sr, uint8_t *original_packet, unsigned int original_packet_len, uint8_t icmp_type,  uint8_t icmp_code,  char *outgoing_iface_name)
{
    // get original patckets eth and ip headers
    struct sr_ethernet_hdr *ethernet_header_original = (struct sr_ethernet_hdr *)original_packet;
    struct sr_ip_hdr *ip_header_original = (struct sr_ip_hdr *)(original_packet + sizeof(struct sr_ethernet_hdr));


 //lengths used for accessing memory in pointer calucalations for headers:
  unsigned int icmp_error_payload_len = sizeof(struct sr_icmp_t3_hdr);  
  unsigned int ip_header_len = sizeof(struct sr_ip_hdr);
  unsigned int ethernet_header_len = sizeof(struct sr_ethernet_hdr);
   unsigned int total_packet_len = ethernet_header_len + ip_header_len + icmp_error_payload_len;

    uint8_t *icmp_error_packet = (uint8_t *)malloc(total_packet_len);
    if (!icmp_error_packet) {
        fprintf(stderr, "ERROR: couldn't allocate memory for icmp error packet\n");
        return;
    }

  //build eth header:
    struct sr_ethernet_hdr *ethernet_header_reply = (struct sr_ethernet_hdr *)icmp_error_packet;
    struct sr_if *outgoing_interface = sr_get_interface(sr, outgoing_iface_name);
    
  memcpy(ethernet_header_reply->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN); //source is us,
  memcpy(ethernet_header_reply->ether_dhost, ethernet_header_original->ether_shost, ETHER_ADDR_LEN); // dest is original packet's
    
    ethernet_header_reply->ether_type = htons(ethertype_ip); 

 
  // ip header
    struct sr_ip_hdr *ip_header_reply = (struct sr_ip_hdr *)(icmp_error_packet + ethernet_header_len);
    //ipv4
  ip_header_reply->ip_v = 4;                      
    ip_header_reply->ip_hl = ip_header_len / 4;     
                
    ip_header_reply->ip_len = htons(ip_header_len + icmp_error_payload_len);

    ip_header_reply->ip_off = htons(0);             
    ip_header_reply->ip_ttl = 64;                
    ip_header_reply->ip_p = ip_protocol_icmp;      
    ip_header_reply->ip_src = outgoing_interface->ip;  //source is now our router
    ip_header_reply->ip_dst = ip_header_original->ip_src;//dest is original sender
    ip_header_reply->ip_sum = 0;
    //ompute checksum
    ip_header_reply->ip_sum = cksum(ip_header_reply, ip_header_len); 

  //icmp error header
    struct sr_icmp_t3_hdr *icmp_header = (struct sr_icmp_t3_hdr *)(icmp_error_packet + ethernet_header_len + ip_header_len);
    icmp_header->icmp_type = icmp_type; //icmp type 
    icmp_header->icmp_code = icmp_code; // icmp Code 
    icmp_header->unused = 0;
    icmp_header->next_mtu = 0;
  //copy over what we have
    memcpy(icmp_header->data, ip_header_original, ICMP_DATA_SIZE);

    //icmp checksum calculations:
    icmp_header->icmp_sum = 0;
    icmp_header->icmp_sum = cksum(icmp_header, icmp_error_payload_len);

    //debug print statement
   // printf("[ICMP ERROR] Sending Type %d, Code %d to interface %s\n", icmp_type, icmp_code, outgoing_iface_name);

    //send the icmp error packet out  the interface as found
    sr_send_packet(sr, icmp_error_packet, total_packet_len, outgoing_iface_name);
    free(icmp_error_packet);
}
