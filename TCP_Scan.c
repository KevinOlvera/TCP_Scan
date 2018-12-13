#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <asm/types.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <linux/rtnetlink.h>
#include <signal.h>

#define TTLPATH "/proc/sys/net/ipv4/ip_default_ttl"
#define ETHTYPE_ARP "\x08\x06"
#define ETHTYPE_IP "\x08\x00"
#define MAC_BROADCAST "\xff\xff\xff\xff\xff\xff"
#define TCP_PROT 6
#define IPTOTLEN 48
#define BUFFER_SIZE 4096
#define PACKETTOTLEN 62

int Hostname_to_IP(char *hostname, char *ip);
int Default_Interface(char *interface_name);
int obtenerDatos(int ds, struct ifreq *interface, unsigned char *My_MAC, unsigned char *My_IP, unsigned char *My_NetMask);
int Host_is_in_Network(unsigned char *ip, unsigned char *netmask, unsigned char *ip_host);
void ARP(int *indice, unsigned char *MACOrigen, unsigned char *IPOrigen, unsigned char *MACDestino, unsigned char *IPDestino);
int ARP_Request(int ds, int *indice, unsigned char *trama_env, unsigned char *MACOrigen, unsigned char *IPOrigen, unsigned char *IPDestino, int trama_len);
void Eth_Header(unsigned char *trama, unsigned char *MACDestino, unsigned char *MACOrigen, unsigned char *eth_type, int trama_len);
void ARP_Header(unsigned char *trama, unsigned char *IPOrigen, unsigned char *IPDestino);
void enviarTrama(int ds, int index, unsigned char *trama_enviar, int trama_len);
void Rec_ARP(int ds, int *indice, unsigned char *trama_rec, unsigned char *MACOrigen, unsigned char *IPDestino, unsigned char *MACDestino, int trama_len);
int recibeTrama(int ds, unsigned char *trama, int trama_len);
int Filter_ARP_Reply(unsigned char *trama, int trama_len, unsigned char *MACDestino, unsigned char *IPOrigen);
int Gateway_Address(unsigned char *IPGateway);
void IP_Header(unsigned char *trama, unsigned int protocol, unsigned char *IPOrigen, unsigned char *IPDestino, int count);
unsigned int getTTL();
unsigned short checksum(unsigned char *buff, int tam);
void TCP_Header(unsigned char *trama, unsigned int puerto_origen, unsigned int puerto_destino, unsigned char *IPOrigen, unsigned char *IPDestino);
void Rec_TCP(int ds, int index, unsigned char *trama_rec, unsigned int puerto_origen, unsigned int puerto_destino, unsigned char *MACOrigen, unsigned char *MACDestino, unsigned char *IPDestino, int trama_len);
int Filter_TCP_Reply(unsigned char *trama, unsigned int puerto_origen, unsigned int puerto_destino, unsigned char *MACOrigen, unsigned char *MACDestino, unsigned char *IPDestino);
void imprimeTrama(unsigned char *trama, int trama_len);

int puertos_cerrados = 0;
int puerto_abierto = 0;
int puerto_sin_respuesta = 0;

int Hostname_to_IP(char *hostname, char *ip)
{
    struct hostent *host;
    struct in_addr **addr_list;
    int i;

    if ((host = gethostbyname(hostname)) == NULL)
        return -1;
    else
    {
        addr_list = (struct in_addr **)host->h_addr_list;
        
        for (i = 0; addr_list[i] != NULL; i++)
            strcpy(ip, inet_ntoa(*addr_list[i]));
        return 1;
    }
}

int Default_Interface(char *interface_name)
{
    int i = 0;
    struct ifaddrs *ifap, *ifa;

    if (getifaddrs(&ifap) != 0)
    {
        perror("Error:");
        freeifaddrs(ifap);
        return -1;
    }
    else
    {
        for (ifa = ifap; ifa; ifa = ifa->ifa_next)
            if (ifa->ifa_addr->sa_family == AF_INET)
            {
                if (i == 1)
                    strcpy(interface_name, ifa->ifa_name);
                i++;
            }

        freeifaddrs(ifap);
        return 1;
    }
}

int obtenerDatos(int ds, struct ifreq *interface, unsigned char *My_MAC, unsigned char *My_IP, unsigned char *My_NetMask)
{
    int index = 0;

    if (ioctl(ds, SIOCGIFINDEX, interface) == -1)
    {
        perror("Error al obtener el indice");
        exit(1);
    }
    else
    {
        index = interface->ifr_ifindex;
    }

    if (ioctl(ds, SIOCGIFHWADDR, interface) == -1)
    {
        perror("Error al obtener la MAC");
        exit(1);
    }
    else
    {
        memcpy(My_MAC, interface->ifr_hwaddr.sa_data, 6);
    }

    if (ioctl(ds, SIOCGIFADDR, interface) == -1)
    {
        perror("Error al obtener la IP");
        exit(1);
    }
    else
    {
        memcpy(My_IP, interface->ifr_addr.sa_data + 2, 4);
    }

    if (ioctl(ds, SIOCGIFNETMASK, interface) == -1)
    {
        perror("Error al obtener la netmask");
        exit(1);
    }
    else
    {
        memcpy(My_NetMask, interface->ifr_netmask.sa_data + 2, 4);
    }

    return index;
}

int Host_is_in_Network(unsigned char *ip, unsigned char *netmask, unsigned char *ip_host)
{
    unsigned char id_network[4];
    unsigned char AND_check[4];

    memcpy(id_network, ip, 4);
    memset(&id_network[3], 0, sizeof(char));

    for (int i = 0; i < 4; i++)
        AND_check[i] = ip_host[i] & netmask[i];
    
    if (!memcmp(AND_check, id_network, 4))
        return 1;
    else
        return 0;
}

void ARP(int *indice, unsigned char *MACOrigen, unsigned char *IPOrigen, unsigned char *MACDestino, unsigned char *IPDestino)
{ 
    unsigned char trama_env[42];
    unsigned char trama_rec[60];

    int trama_env_len = (int)sizeof(trama_env), trama_rec_len = (int)sizeof(trama_rec);

    int ds = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (ds == -1)
    {
        perror("Error al abrir el socket");
        exit(1);
    }
    
    ARP_Request(ds, indice, trama_env, MACOrigen, IPOrigen, IPDestino, trama_env_len);
    Rec_ARP(ds, indice, trama_rec, MACOrigen, IPDestino, MACDestino, trama_rec_len);

    close(ds);
}

int ARP_Request(int ds, int *indice, unsigned char *trama_env, unsigned char *MACOrigen, unsigned char *IPOrigen, unsigned char *IPDestino, int trama_len)
{
    Eth_Header(trama_env, MAC_BROADCAST, MACOrigen, ETHTYPE_ARP, trama_len);
    ARP_Header(trama_env, IPOrigen, IPDestino);
    enviarTrama(ds, *indice, trama_env, trama_len);
}

void Eth_Header(unsigned char *trama, unsigned char *MACDestino, unsigned char *MACOrigen, unsigned char *eth_type, int trama_len)
{
    memset((void *)trama, 0, trama_len);
    memcpy(trama + 0, MACDestino, 6);
    memcpy(trama + 6, MACOrigen, 6);
    memcpy(trama + 12, eth_type, 2);
}

void ARP_Header(unsigned char *trama, unsigned char *IPOrigen, unsigned char *IPDestino)
{
    memcpy(trama + 14, "\x00\x01", 2);  //Hardware Type
    memcpy(trama + 16, "\x08\x00", 2);  //Protocol Type
    memcpy(trama + 18, "\x06", 1);      //Hardware Address Length
    memcpy(trama + 19, "\x04", 1);      //Protocol Address Length
    memcpy(trama + 20, "\x00\x01", 2);  //Operation Code
    memcpy(trama + 22, trama + 6, 6);   //Source Hardware Address
    memcpy(trama + 28, IPOrigen, 4);    //Source Protocol Address
    memcpy(trama + 38, IPDestino, 4);   //Target Protocol Address
}

void enviarTrama(int ds, int index, unsigned char *trama_enviar, int trama_len)
{
    int tam;
    struct sockaddr_ll interface;

    memset(&interface, 0x00, sizeof(interface));

    interface.sll_family = AF_PACKET;
    interface.sll_protocol = htons(ETH_P_ALL);
    interface.sll_ifindex = index;
    
    tam = sendto(ds, trama_enviar, trama_len, 0, (struct sockaddr *)&interface, sizeof(interface));
    
    if (tam == -1)
        perror("Error al enviar la trama");
}

void Rec_ARP(int ds, int *indice, unsigned char *trama_rec, unsigned char *MACOrigen, unsigned char *IPDestino, unsigned char *MACDestino, int trama_len)
{
    struct timeval start, end;
    int tam, flag = 0;
    long mtime = 0, seconds, useconds;

    gettimeofday(&start, NULL);

    while (mtime < 500)
    {
        tam = recvfrom(ds, trama_rec, trama_len, MSG_DONTWAIT, NULL, 0);

        if( tam == -1 )
		{
			//perror("Error al recibir");
		}
		else
		{
            if (Filter_ARP_Reply(trama_rec, trama_len, MACOrigen, IPDestino) == 1)
            {
                memcpy(MACDestino, trama_rec + 22, 6);
                printf(" ");
                for (int i = 0; i < 6; i++)
                    if (i == 5)
                        printf("%.2X", MACDestino[i]);
                    else
                        printf("%.2X:", MACDestino[i]);

                printf(" - ");

                for (int i = 0; i < 4; i++)
                    if (i == 3)
                        printf("%d", IPDestino[i]);
                    else
                        printf("%d.", IPDestino[i]);

                flag = 1;
            }
		}
        
        gettimeofday(&end, NULL);
        seconds = end.tv_sec - start.tv_sec;
        useconds = end.tv_usec - start.tv_usec;
        mtime = ((seconds)*1000 + useconds / 1000.0) + 0.5;
        
        if (flag == 1)
            break;
    }

    if (flag == 0)
    {
        perror("Sin respuesta ARP");
        exit(1);
    }
}

int recibeTrama(int ds, unsigned char *trama, int trama_len)
{
    int tam = 0;
    tam = recvfrom(ds, trama, trama_len, MSG_DONTWAIT, NULL, 0);
    return tam;
}

int Filter_ARP_Reply(unsigned char *trama, int trama_len, unsigned char *MACDestino, unsigned char *IPOrigen)
{
    if (!memcmp(trama + 0, MACDestino, 6) && !memcmp(trama + 12, ETHTYPE_ARP, 2) && !memcmp(trama + 20, "\x00\x02", 2) && !memcmp(trama + 28, IPOrigen, 4) && !memcmp(trama + 32, MACDestino, 6))
        return 1;
    return -1;
}

int Gateway_Address(unsigned char *IPGateway)
{
    int received_bytes = 0, msg_len = 0, route_attribute_len = 0;
    int ds, msgseq = 0;
    struct nlmsghdr *nlh, *nlmsg;
    struct rtmsg *route_entry;
    struct rtattr *route_attribute;
    char gateway_address[INET_ADDRSTRLEN], interface[IF_NAMESIZE];
    char msgbuf[BUFFER_SIZE], buffer[BUFFER_SIZE];
    char *aux = buffer;
    struct timeval tv;

    if ((ds = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0)
    {
        perror("Socket failed");
        return 0;
    }

    memset(msgbuf, 0, sizeof(msgbuf));
    memset(gateway_address, 0, sizeof(gateway_address));
    memset(interface, 0, sizeof(interface));
    memset(buffer, 0, sizeof(buffer));

    nlmsg = (struct nlmsghdr *)msgbuf;
    nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlmsg->nlmsg_type = RTM_GETROUTE;                       // Get the routes from kernel routing table .
    nlmsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;        // The message is a request for dump.
    nlmsg->nlmsg_seq = msgseq++;                            // Sequence of the message packet.
    nlmsg->nlmsg_pid = getpid();
    tv.tv_sec = 1;

    setsockopt(ds, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval));
    /* send msg */
    if (send(ds, nlmsg, nlmsg->nlmsg_len, 0) < 0)
    {
        perror("Send failed");
        return 0;
    }

    do
    {
        received_bytes = recv(ds, aux, sizeof(buffer) - msg_len, 0);
        
        if (received_bytes < 0)
        {
            perror("Error in recv");
            return 0;
        }

        nlh = (struct nlmsghdr *)aux;

        if ((NLMSG_OK(nlmsg, received_bytes) == 0) ||
            (nlmsg->nlmsg_type == NLMSG_ERROR))
        {
            perror("Error in received packet");
            return 0;
        }
        
        if (nlh->nlmsg_type == NLMSG_DONE)
            break;
        else
        {
            aux += received_bytes;
            msg_len += received_bytes;
        }

        if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0)
            break;
    } while ((nlmsg->nlmsg_seq != msgseq) || (nlmsg->nlmsg_pid != getpid()));

    for (; NLMSG_OK(nlh, received_bytes); nlh = NLMSG_NEXT(nlh, received_bytes))
    {
        route_entry = (struct rtmsg *)NLMSG_DATA(nlh);
        
        if (route_entry->rtm_table != RT_TABLE_MAIN)
            continue;

        route_attribute = (struct rtattr *)RTM_RTA(route_entry);
        route_attribute_len = RTM_PAYLOAD(nlh);
        
        for (;RTA_OK(route_attribute, route_attribute_len);route_attribute = RTA_NEXT(route_attribute, route_attribute_len))
        {
            switch (route_attribute->rta_type)
            {
            case RTA_OIF:
                if_indextoname(*(int *)RTA_DATA(route_attribute), interface);
                break;
            case RTA_GATEWAY:
                inet_ntop(AF_INET, RTA_DATA(route_attribute), gateway_address, sizeof(gateway_address));
                break;
            default:
                break;
            }
        }

        if ((*gateway_address) && (*interface))
        {
            inet_aton(gateway_address, (struct in_addr *)IPGateway);
            return 1;
        }
    }

    close(ds);
    return 0;
}

void IP_Header(unsigned char *trama, unsigned int protocol, unsigned char *IPOrigen, unsigned char *IPDestino, int count)
{
    struct timeval time;
    unsigned char identifier[2];
    unsigned char checksum_uc[2];
    unsigned short checksum_ush;
    unsigned int TTL = getTTL();
    unsigned char *aux, *aux_1;
    unsigned char temp_header[20];
    int id;
    
    gettimeofday(&time, NULL);
    srand((time.tv_sec * 10000) + (time.tv_usec / 10000));
    id = (rand() % 100000) + (count + 1);
    
    aux = (char *)&id;
    aux_1 = aux;

    for (&aux; *aux; aux++)
        identifier[(int)(aux - aux_1)] = *aux;

    memcpy(trama + 14, "\x45", 1);          //version y longitud de encabezado
    memset(trama + 17, IPTOTLEN, 1);        //Total Length
    memset(trama + 18, identifier[1], 1);   //Identificador
    memset(trama + 19, identifier[0], 1);   //Identificador
    memcpy(trama + 20, "\x40", 1);          //Flags 0x40 is equal to "do not fragment"
    memset(trama + 22, TTL, 1);             //Time To live
    memset(trama + 23, protocol, 1);        //Protocol
    memset(trama + 24, 0, 2);               //SET CHECKSUM 0
    memcpy(trama + 26, IPOrigen, 4);        //Source IP Address
    memcpy(trama + 30, IPDestino, 4);       //Target IP Address
    
    memcpy(temp_header, trama + 14, (int)sizeof(temp_header));
    checksum_ush = checksum(temp_header, sizeof(temp_header));
    aux = (char *)&checksum_ush;
    aux_1 = aux;

    for (&aux; *aux; aux++)
        checksum_uc[(int)(aux - aux_1)] = *aux;
    
    memset(trama + 24, checksum_uc[1], 1);
    memset(trama + 25, checksum_uc[0], 1);
}

unsigned int getTTL()
{
    int i = 0;
    char x;
    unsigned char stringttl[4];
    FILE *filettl = NULL;

    filettl = fopen(TTLPATH, "r");

    if (filettl == NULL)
    {
        perror("No se pudo abrir el archivo");
        exit(1);
    }
    
    fread(&x, sizeof(char), 1, filettl);
    
    while (!feof(filettl))
    {
        stringttl[i] = x;
        fread(&x, sizeof(char), 1, filettl);
        i++;
    }
    
    fclose(filettl);

    return atoi(stringttl);
}

unsigned short checksum(unsigned char *buff, int tam)
{
    unsigned short checksum_ush = 0;
    unsigned short acarreo = 0;
    int i, suma = 0, resultado = 0, temp = 0;

    for (i = 0; i < tam; i = i + 2)
    {
        temp = (buff[i] << 8) + buff[i + 1];
        suma = suma + temp;
        temp = 0;
    }
    
    acarreo = suma >> 16;
    resultado = (suma & 0x0000FFFF) + acarreo;
    acarreo = resultado >> 16;
    resultado = (resultado & 0x0000FFFF) + acarreo;
    checksum_ush = 0xffff - resultado;
    
    return checksum_ush;
}

void TCP_Header(unsigned char *trama, unsigned int puerto_origen, unsigned int puerto_destino, unsigned char *IPOrigen, unsigned char *IPDestino)
{
    int len = PACKETTOTLEN - 34;
    len = htons(len);

    memcpy(trama + 34, (char *)&puerto_origen, 2);  //Source port
    memcpy(trama + 36, (char *)&puerto_destino, 2); //Destination port
    memcpy(trama + 38, "\xb7\x47\x4c\xcc", 4);      //Sequence Number
    memset(trama + 42, 0, 4);                       //ACK
    memcpy(trama + 46, "\x70\x02", 2);              //Longitud de encabezado y flag SYN encendida
    memcpy(trama + 48, "\x40\x00", 2);              //Winsize
    memset(trama + 50, 0, 2);                       //Set checksum field to zero
    memset(trama + 52, 0, 2);                       //Urgent pointer disabled
    memcpy(trama + 54, "\x02\x04\x05\xb4\x01\x01\x04\x02", 8);

    unsigned char pseudo_header[12];
    memset(&pseudo_header, 0, sizeof(pseudo_header));
    
    memcpy(pseudo_header + 0, IPOrigen, 4);
    memcpy(pseudo_header + 4, IPDestino, 4);
    memset(pseudo_header + 9, 6, 1);
    memcpy(pseudo_header + 10, (char *)&len, 2);
    
    unsigned char tempTCPHeader[40];
    memset(&tempTCPHeader, 0, sizeof(tempTCPHeader));
    
    memcpy(tempTCPHeader + 0, pseudo_header, 12);
    memcpy(tempTCPHeader + 12, trama + 34, 28);
    
    unsigned short checksum_ush = checksum(tempTCPHeader, (int)sizeof(tempTCPHeader));
    checksum_ush = htons(checksum_ush);
    memcpy(trama + 50, (char *)&checksum_ush, 2); //Set checksum;
}

void Rec_TCP(int ds, int index, unsigned char *trama_rec, unsigned int puerto_origen, unsigned int puerto_destino, unsigned char *MACOrigen, unsigned char *MACDestino, unsigned char *IPDestino, int trama_len)
{
    struct timeval start, end;
    int flag = 0, tam;
    long mtime = 0, seconds, useconds;

    gettimeofday(&start, NULL);
    
    while (mtime < 300)
    {
        tam = recibeTrama(ds, trama_rec, trama_len);

        if( tam == -1 )
		{
			//perror("Error al recibir");
		}
		else
		{
            switch(Filter_TCP_Reply(trama_rec, puerto_origen, puerto_destino, MACOrigen, MACDestino, IPDestino))
            {
                case 1:
                    //printf("\tAbierto");
                    //imprimeTrama(trama_rec, trama_len);
                    puerto_abierto = 1;
                    puerto_sin_respuesta = 0;
                    flag = 1;
                break;
                case 0:
                    //printf("\t Cerrado");
                    //imprimeTrama(trama_rec, trama_len);
                    puerto_abierto = 0;
                    puerto_sin_respuesta = 0;
                    puertos_cerrados++;
                    flag = 1;
                break;
                case -1:
                    flag = 0;
                break;
                default:
                break;
            }

            gettimeofday(&end, NULL);
            seconds = end.tv_sec - start.tv_sec;
            useconds = end.tv_usec - start.tv_usec;
            mtime = ((seconds)*1000 + useconds / 1000.0) + 0.5;
           
            if (flag == 1)
                break;
		}
    }

    if (flag == 0)
    {
        //printf(" Sin respuesta de filtro TCP\n");
        puerto_sin_respuesta = 1;
    }
}

int Filter_TCP_Reply(unsigned char *trama, unsigned int puerto_origen, unsigned int puerto_destino, unsigned char *MACOrigen, unsigned char *MACDestino, unsigned char *IPDestino)
{
    unsigned char puertos[4];

    memcpy(puertos + 0, (char *)&puerto_destino, 2);
    memcpy(puertos + 2, (char *)&puerto_origen, 2);

    //!memcmp(trama + 47, "\x014", 1)
    //!memcmp(trama + 47, "\x012", 1) //Si esta abierto

    if (!memcmp(trama, MACOrigen, 6) && !memcmp(trama + 6, MACDestino, 6) && !memcmp(trama + 12, ETHTYPE_IP, 2) && !memcmp(trama + 23, "\x06", 1) && !memcmp(trama + 26, IPDestino, 4) && !memcmp(trama + 34, puertos, 4))
    {
        //printf("Trama recibida de puerto abierto\n");
        //imprimeTrama(trama, 50);

        if( !memcmp(trama + 47, "\x12", 1))
            return 1;
        else if( !memcmp(trama + 47, "\x14", 1))
            return 0;
    }
    else
        return -1;
}

void imprimeTrama(unsigned char *trama, int trama_len)
{
    for (int i = 0; i < trama_len; i++)
    {
        if (i % 16 == 0)
            printf("\n");
        printf("%.2X ", *(trama + i));
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    char *hostname = argv[1];
    int port_1, port_2;
    char IPDestino_string[15], name_interface[10];
    unsigned char My_MAC[6], My_IP[4], My_NetMask[4];
    unsigned char MACDestino[6], IPDestino[4];
    unsigned char IPGateway[4];
    int ds = 0, indice = 0;
    struct ifreq interface;
    unsigned char trama_tcp[PACKETTOTLEN];
    unsigned char trama_rec[100];

    port_1 = atoi(argv[2]);
    port_2 = atoi(argv[3]);

    if (argc != 4)
    {
        printf("Ingresar parametros: %s [IP_Address/Hostname] [P_Inicial] [P_Final]\n", argv[0]);
        exit(1);
    }

    if (Hostname_to_IP(hostname, IPDestino_string) == -1)
    {
        printf("Direccion Invalida :(");
        exit(1);
    }

    ds = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
   
    if (ds == -1)
    {
        perror("Error al abrir el socket");
        exit(1);
    }

    if (Default_Interface(name_interface) == -1)
    {
        printf("Error al conseguir la interfaz");
        exit(1);
    }

    strcpy(interface.ifr_name, name_interface);

    indice = obtenerDatos(ds, &interface, My_MAC, My_IP, My_NetMask);
    
    inet_aton(IPDestino_string, (struct in_addr *)IPDestino);
    
    printf("+-------------------------------+\n");

    if (Host_is_in_Network(My_IP, My_NetMask, IPDestino))
    {
        if(!memcmp(IPDestino, My_IP, 6))
            memcpy(MACDestino, My_MAC, 6);
        ARP(&indice, My_MAC, My_IP, MACDestino, IPDestino);
    }
    else
    {
        Gateway_Address(IPGateway);
        ARP(&indice, My_MAC, My_IP, MACDestino, IPGateway);
    }

    printf("\n+-------------------------------+\n");
    printf(" Escaneando los puertos %d - %d\n", port_1, port_2);
    printf("+-------------------------------+\n");
    printf(" Puerto(s)\tEstado\n");
    printf("+-------------------------------+\n");

    for (int port = port_1; port <= port_2; port++)
    {
        Eth_Header(trama_tcp, MACDestino, My_MAC, ETHTYPE_IP, (int)sizeof(trama_tcp));
        IP_Header(trama_tcp, TCP_PROT, My_IP, IPDestino, port);
        TCP_Header(trama_tcp, htons(61000), htons(port), My_IP, IPDestino);
        enviarTrama(ds, indice, trama_tcp, (int)sizeof(trama_tcp));
        //printf("Trama enviada");
        //imprimeTrama(trama_tcp, (int)sizeof(trama_tcp));
        //printf(" %d", port);
        
        memset(&trama_rec, 0, sizeof(trama_rec));

        Rec_TCP(ds, indice, trama_rec, htons(61000), htons(port), My_MAC, MACDestino, IPDestino, sizeof(trama_rec));

        if(puerto_abierto)
            printf(" %d\t\tAbierto\n", port);

        if(puerto_sin_respuesta)
            printf(" %d\t\tSin Respuesta\n", port);
    }

    printf(" %d\t\tCerrado(s)\n", puertos_cerrados);

    close(ds);
    
    return 0;
}