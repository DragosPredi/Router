#include "skel.h"
int countNrLines(){
	FILE *fileptr;
    int linesCount = 0;
    char ch;
 
    fileptr = fopen("rtable.txt", "r");

	 while((ch=fgetc(fileptr))!=EOF) {
      if(ch=='\n')
         linesCount++;
   }
   fclose(fileptr);

   return linesCount;
}

struct rtable* tableroniParseroni(){
	int nrEntries = countNrLines();
	struct rtable *table = (struct rtable*)malloc(nrEntries * sizeof(struct rtable));
	char prefix[50], nextHop[50], mask[50], interface[50];
	FILE *fileptr;
	fileptr = fopen("rtable.txt", "r");

	for(int i = 0 ; i < nrEntries ; i++){
		fscanf(fileptr, "%s", prefix);
		fscanf(fileptr, "%s", nextHop);
		fscanf(fileptr, "%s", mask);
		fscanf(fileptr, "%s", interface);
		table[i].prefix = inet_addr(prefix);
		table[i].nextHop = inet_addr(nextHop);
		table[i].mask = inet_addr(mask);
		table[i].interface = interface[0] - 48; 
	}
	fclose(fileptr);
	return table;
}

int check_same_entry(uint8_t *ip, uint8_t *mac, struct cached_arp_table *myArpTable){
	
	for(int j = 0 ; j < myArpTable->nrEntries ; j++){
		int same = 1;
		for(int i = 0 ; i < 4 ; i++){
			if(ip[i] != myArpTable->entries[j].ip[i])
				same = 0;
		}
		for(int i = 0 ; i < 6 ; i++){
			if(mac[i] != myArpTable->entries[j].mac[i])
				same = 0;
		}
		if(same == 1)
			return 1;
	}
	return 0;
}

int send_and_cache_ARP_request(int interface, u_char *ip, struct cached_arp_table *myArpTable){
	
	packet m;

	const size_t sizeof_buf = ETHER_HDR_LEN + sizeof(struct arp_packet);
	u_char packet_data[sizeof_buf];

	struct ether_header *ethHeader = NULL;
	struct arp_packet *ethArp = NULL;

	ethHeader = (struct ether_header *) packet_data;
	ethArp = (struct arp_packet *) (packet_data + ETHER_HDR_LEN);

	//configure Ether Header
	//get router MAC address
	uint8_t *routerMac = malloc(6 * sizeof(uint8_t));
	get_interface_mac(interface, routerMac);

	for(int i = 0 ; i < 6 ; i++){
		ethHeader->ether_dhost[i] = 255;
		ethHeader->ether_shost[i] = routerMac[i];
	}

	ethHeader->ether_type = htons(ETHERTYPE_ARP);

	//configure ARP packet

	//hardware
	ethArp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);

	//protocol type
	ethArp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);

	//hardware address length
	ethArp->ea_hdr.ar_hln = ETH_ALEN;

	//protocol address length
	ethArp->ea_hdr.ar_pln = 4;

	//operation
	ethArp->ea_hdr.ar_op = htons(ARPOP_REQUEST);

	//source and target MAC
	for(int i = 0 ; i < 6 ; i++){
		ethArp->arp_sha[i] = routerMac[i];
		ethArp->arp_tha[i] = 0;
	}
	//source IP
	inet_pton(AF_INET, get_interface_ip(interface), &ethArp->arp_spa);
	//target IP
	for(int i = 0 ; i < 4 ; i++){
		ethArp->arp_tpa[i] = ip[i];
	}


	memcpy(&m.payload, packet_data, sizeof_buf);
	m.len = sizeof_buf;
	m.interface = interface;

	send_packet(interface, &m);
	//recieve msg
	int rc = get_packet(&m);
	DIE(rc < 0, "get_message");

	ethHeader = (struct ether_header *)m.payload;
	ethArp = (struct arp_packet *)(m.payload + sizeof(struct ether_header));

	struct cached_arp_addr newEntry;
	//get the entry
	for(int i = 0 ; i < 4 ; i++)
		newEntry.ip[i] = ethArp->arp_spa[i];

	for(int i = 0 ; i < 6 ; i++)
		newEntry.mac[i] = ethArp->arp_sha[i];
	//cache it the table has space and the entry is good
	if(myArpTable->capacity > 0 && (check_same_entry(ethArp->arp_spa, ethArp->arp_sha, myArpTable) == 0)){
		myArpTable->entries[myArpTable->nrEntries] = newEntry;
		myArpTable->nrEntries++;
		myArpTable->capacity--;
	}
	//realloc and then cache if the table has no more space
	else if(myArpTable->capacity <= 0 && (check_same_entry(ethArp->arp_spa, ethArp->arp_sha, myArpTable) == 0)){
		myArpTable->entries = realloc(myArpTable->entries, myArpTable->capacity * 2);
		myArpTable->capacity *= 2;

		myArpTable->entries[myArpTable->nrEntries] = newEntry;
		myArpTable->nrEntries++;
		myArpTable->capacity--;

	}
	free(routerMac);

	return 0;
}

int get_mac(uint8_t *ip, uint8_t *macBuff, struct cached_arp_table *myArpTable){
	for(int i = 0 ; i < myArpTable->nrEntries ; i++){
		int ok = 1;
		printf("in get mac%d\n", i);
		for(int j = 0 ; j < 4; j++){
			if(ip[j] != myArpTable->entries[i].ip[j])
				ok = 0;
		}
		if(ok == 1){
			for(int j = 0 ; j < 6 ; j++){
				macBuff[j] = myArpTable->entries[i].mac[j];
			}
			printf("in get mac ok %d\n", ok);

			return 1;
		}
	}
	return 0;
}

void send_icmp(int interface, uint32_t sender, uint32_t dest, uint8_t *destMac, int type){
	packet newM;

	const size_t sizeof_buf = ETHER_HDR_LEN + sizeof(struct iphdr) + sizeof(struct icmphdr);
	u_char packet_data[sizeof_buf];

	newM.len = sizeof_buf;
	newM.interface = interface;


	struct ether_header *newEthHeader = NULL;
	struct iphdr *newIp_hdr = NULL;
	struct icmphdr *newIcmp_hdr = NULL;

	newEthHeader = (struct ether_header *) packet_data;
	newIp_hdr = (struct iphdr *)(packet_data + ETHER_HDR_LEN);
	newIcmp_hdr = (struct icmphdr *)(packet_data + ETHER_HDR_LEN + sizeof(struct iphdr));

	//fill IP header
	newIp_hdr->version = 4;
	newIp_hdr->ihl = 5;
	newIp_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	newIp_hdr->tos = 0;
	newIp_hdr->id = htons(getpid());
	newIp_hdr->ttl = 64;
	newIp_hdr->frag_off = 0;
	newIp_hdr->saddr = sender;
	newIp_hdr->daddr = dest;
	newIp_hdr->protocol = IPPROTO_ICMP;
	newIp_hdr->check = 0;
	newIp_hdr->check = ip_checksum(newIp_hdr, sizeof(struct iphdr));
	//fipp ICMP header
	newIcmp_hdr->type = type;
	newIcmp_hdr->code = 0;
	newIcmp_hdr->un.echo.id = htons(getpid());
	newIcmp_hdr->un.echo.sequence = htons(0);
	newIcmp_hdr->checksum = 0;
	newIcmp_hdr->checksum = ip_checksum(newIcmp_hdr, sizeof(struct icmphdr));


	uint8_t *routerMac = malloc(6 * sizeof(uint8_t));
	get_interface_mac(newM.interface, routerMac);
	//fill ETHER header
	for(int i = 0 ; i < 6 ; i++){
		newEthHeader->ether_dhost[i] = destMac[i];
		newEthHeader->ether_shost[i] = routerMac[i];
	}
	newEthHeader->ether_type = htons(ETHERTYPE_IP);

	memcpy(&newM.payload, packet_data, sizeof_buf);

	send_packet(newM.interface, &newM);

}

void get_ip_vector_format(uint32_t ip, uint8_t *buff){

	for (int i = 0; i < 4; i++)
	    buff[i] = ( ip >> (i*8) ) & 0xFF;

}

int compare(const void *a, const void *b){
	const struct rtable *aa = (struct rtable *)a;
	const struct rtable *bb = (struct rtable *)b;

	if(aa->prefix < bb->prefix){
		return -1;
	}
	else if(aa->prefix == bb->prefix){
		if(aa->mask < bb->mask)
			return -1;
		else if(aa->mask == bb->mask)
			return 0;
		else
			return 1;
	}
	else{
		return 1;
	}
}

int bin_search(struct rtable *table, uint32_t ip, int low, int high){
	
	if(low > high)
		return -1;

	int mid = low + ((high - low) >> 1);

	if((table[mid].mask & ip) == table[mid].prefix)
		return mid;

	if((table[mid].mask & ip) < table[mid].prefix)
		return bin_search(table, ip, low, mid - 1);
	else
		return bin_search(table, ip, mid + 1, high);
}

struct rtable *get_best_routeBin(uint32_t ip, struct rtable *table,  int nrRTEntries){

	int id = bin_search(table, ip, 0, nrRTEntries);
	int p;
	uint32_t final;
	int idAux = id;
	
	while((table[idAux].mask & ip) == table[idAux].prefix){
		if(table[idAux].mask > final){
				final = table[idAux].mask;
				p = idAux;
			}
		idAux--;
	}

	while((table[id].mask & ip) == table[id].prefix){
		if(table[id].mask > final){
				final = table[id].mask;
				p = id;
			}
		id++;
	}

	if((table[p].mask & ip) == table[p].prefix){
		return &table[p];
	}
	else
		return NULL;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;
	//Parse routing table
	int nrRTEntries = countNrLines();
	struct rtable *table = tableroniParseroni();
	//ordonez table pt a putea folosi cautare binara
	qsort(table, nrRTEntries, sizeof(struct rtable), compare);

	//create structure for local ARP table
	struct cached_arp_table *myArpTable = (struct cached_arp_table*)malloc(sizeof(struct cached_arp_table));
	myArpTable->entries = (struct cached_arp_addr*)malloc(10 * sizeof(struct cached_arp_addr));
	myArpTable->capacity = 10;
	myArpTable->nrEntries = 0;

	queue q;
	q = queue_create();

	init();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct ether_header *ethHeader = (struct ether_header *)m.payload;
		//if it's an ARP packet
		if(ntohs(ethHeader->ether_type) == ETHERTYPE_ARP){
			struct arp_packet *ethArp = (struct arp_packet *)(m.payload + sizeof(struct ether_header));
			
			if(ntohs(ethArp->ea_hdr.ar_op) == ARPOP_REQUEST){
				//get router MAC address
				uint8_t *routerMac = malloc(6 * sizeof(uint8_t));
				get_interface_mac(m.interface, routerMac);
				
				for(int i = 0 ; i < 6 ; i++){
					ethArp->arp_tha[i] = ethArp->arp_sha[i];
					ethHeader->ether_dhost[i] = ethArp->arp_sha[i];

					ethArp->arp_sha[i] = routerMac[i];
					ethHeader->ether_shost[i] = routerMac[i];
				}
				//setting up ip in arp header
				for(int i = 0 ; i < 4 ; i++)
					ethArp->arp_tpa[i] = ethArp->arp_spa[i];
				//seting ip of router in arp header
				inet_pton(AF_INET, get_interface_ip(m.interface), &ethArp->arp_spa);

				ethArp->ea_hdr.ar_op = htons(ARPOP_REPLY);	

				send_packet(m.interface, &m);
			}
		}
		//if it's an IP packet
		if(ntohs(ethHeader->ether_type) == ETHERTYPE_IP){
			//get iphdr header
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
			uint32_t routerIP = inet_addr(get_interface_ip(m.interface));
			//if the destination is the router send echo reply
			if(ip_hdr->daddr == routerIP){
				ip_hdr->daddr = ip_hdr->saddr;
				ip_hdr->saddr = routerIP;
				ip_hdr->ttl = 64;
				ip_hdr->check = 0;
				ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

				struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
				icmp_hdr->type = ICMP_ECHOREPLY;
				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));

				send_packet(m.interface, &m);
				continue;
			}
			//if the checksum is wrong drop the packet
			if(ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0){
				continue;
			}
			//get next hop
			struct rtable *bestRoute = get_best_routeBin(ip_hdr->daddr, table , nrRTEntries);
			//if I find a route
			if(bestRoute != NULL){
				uint8_t macBuff[6];
				uint8_t ipVectorRepr[4] = {0, 0, 0, 0};
				//get the uint_8t represenetation of IP
				get_ip_vector_format(bestRoute->nextHop, ipVectorRepr);
				//if I don't have the MAC I send a request
				if(get_mac(ipVectorRepr, macBuff, myArpTable) == 0){
					void *addr = &m;
					
					queue_enq(q, addr);
					
					send_and_cache_ARP_request(bestRoute->interface, ipVectorRepr, myArpTable);
				
					get_mac(ipVectorRepr, macBuff, myArpTable);

					addr =(packet*) queue_deq(q);
				}
				//fill the ETHER header
				uint8_t routerMac[6];
				get_interface_mac(m.interface, routerMac);

				for(int i = 0 ; i < 6 ; i++){
					ethHeader->ether_dhost[i] = macBuff[i];
					ethHeader->ether_shost[i] = routerMac[i];
				}

				//decrement TTL and update checksum
				if(ip_hdr->ttl >= 2){
					ip_hdr->ttl--;
					ip_hdr->check = 0;
					ip_hdr->check = ip_checksum(ip_hdr,sizeof(struct iphdr));
					send_packet(bestRoute->interface, &m);
				} else { //if time exceeded send ICMP_TIME_EXCEEDED
					send_icmp(m.interface, routerIP, ip_hdr->saddr, ethHeader->ether_shost, ICMP_TIME_EXCEEDED);
					continue;
				}

			} else {//if I don't find route sned ICMP_DEST_UNREACH
				send_icmp(m.interface, routerIP, ip_hdr->saddr, ethHeader->ether_shost, ICMP_DEST_UNREACH);
			}
		}

	}

	free(myArpTable->entries);
	free(myArpTable);
	free(table);
	
}
