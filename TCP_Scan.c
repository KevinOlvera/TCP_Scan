#include "comnet.c"

int main(int argc, char const *argv[])
{
    int packet_socket, index;
    char ip_scan[15];

    packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (packet_socket == -1)
    {
        perror(" Error al abrir el socket");
        exit(1);
    }
    else
    {
        perror(" Exito al abrir el socket");
        index = getData(packet_socket);

        printf(" Ingresa la IP a escanear\n -> ");
        scanf("%s", ip_scan);

        inet_pton(AF_INET, ip_scan, dest_IP);

        if (!isLocalIP(dest_IP))
        {
            getGatewayIP(dest_IP);
            printf("\n Gateway:\t%s\n", IPToString(dest_IP));
        }

        if(memcmp(dest_IP, my_IP, 4))
        {
            ARPframe(frame_s, my_MAC, my_IP, dest_MAC, dest_IP);
            //printFrame(frame_s, 43);
            sendFrame(packet_socket, index, frame_s, 42);
            receiveARPFrame(packet_socket, frame_r);
        }
        else
        {
            memcpy(dest_MAC, my_MAC, 6);
        }

        inet_pton(AF_INET, ip_scan, IP);

        TCP_Scan(packet_socket, index);
    }

    close(packet_socket);
    return 1;
}