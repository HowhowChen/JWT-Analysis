package main

import (
    "fmt"
    "log"
    "errors"
    "regexp"
    "strings"
    "encoding/base64"
    "encoding/json"
    "time"
    "os"
    "path/filepath"
    
    "github.com/google/gopacket"
    _"github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

var (
    dataPath    string
    outputPath  string
    pcapFile    string
    handle     *pcap.Handle
    err         error
)

func init() {
    basePath, _ := os.Getwd()
    dataPath = filepath.Join(basePath, "data")
    outputPath = filepath.Join(basePath, "output")
}

type DataInfo struct {
    Data    []PacketInfo    `json:"data"`
}

type PacketInfo struct {
    IP              string   `json:"ip"`
    Packets         []Packet `json:"packets"`
}

type Packet struct {
    FileName      string  `json:"file_name"`
    Host          string  `json:"host,omitempty"`
    ArrivalTime   string  `json:"arrival_time"`
    ExpTime       string  `json:"exp_time"`
    Jwt           string  `json:"jwt"`
    DecodePayload string  `json:"decode_payload"`
}

func extractHostFromHTTPHeader(payload []byte) string {
	re := regexp.MustCompile(`Host: (.+)`)
	match := re.FindSubmatch(payload)
	if len(match) >= 2 {
		return string(match[1])
	}

	return ""
}

func extractAuthorizationFromHTTPHeader(payload []byte) string {
    re := regexp.MustCompile(`Authorization: Bearer (.+)`)
    match := re.FindSubmatch(payload)
    if len(match) >= 2 {
        return string(match[1])
    }
    
    return ""
}

func extractJWTPayload(jwt string) string {
    return strings.Split(jwt, ".")[1]
}

func decodePayloadToJSON(payload string) (map[string]interface{}, error) {
    // JWT is using RawURLEncoding
    bytes, _ := base64.RawURLEncoding.DecodeString(payload)
    
    var JSON map[string]interface{}

    err = json.Unmarshal(bytes, &JSON)
    if err != nil {
        return nil, errors.New("The JWT Payload JSON Parse Error")
    }

    return JSON, nil
}

func expTimeCovert(exp int64) string {

    tm := time.Unix(exp, 0)
    return tm.Format("2006-01-02 15:04:05")
}

func mkDir(dirName string) error {
    err := os.Mkdir(dirName, 0777)
    if err == nil {
        return nil
    }

    if os.IsExist(err) {
        // Check the existing path is a directory
        info, err := os.Stat(dirName)
        if err != nil {
            return err
        }
        if !info.IsDir() {
            return errors.New("The path exists but is not a directory")
        }
        return nil
    }
    return err  
}

func (p *PacketInfo) printPacketInfo(packet gopacket.Packet, fileName string) error {
    arrivalTime := packet.Metadata().Timestamp
    NewArrivalTime := arrivalTime.Format("2006-01-02 15:04:05")

    /**
    ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
    if ethernetLayer != nil {
        fmt.Println("Ethernet layer detected")
        ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)

        fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)

        fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
        
        // Ethernet type is typically IPv4 but could be ARP or other
        fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
    }
    
    ipLayer := packet.Layer(layers.LayerTypeIPv4)
    if ipLayer != nil {
        fmt.Println("IPv4 layer detected.")
        ip, _ := ipLayer.(*layers.IPv4)
        // IP layer variables:
        // Version (Either 4 or 6)
        // IHL (IP Header Length in 32-bit words)
        // TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
        // Checksum, SrcIP, DstIP
        fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
        fmt.Println("Protocol: ", ip.Protocol)
        fmt.Println()
    }**/
    
    // Application Layer
    applicationLayer := packet.ApplicationLayer()
    if applicationLayer != nil {
        payload := applicationLayer.Payload()
        var packetHost string
        if host := extractHostFromHTTPHeader(payload); host != "" {
            packetHost = strings.Split(host, "\r")[0]
		}
        
        if jwt := extractAuthorizationFromHTTPHeader(payload); jwt != "" {
            
            // Check if the pcap file is existed
            flag := true
            for _, packet := range p.Packets {
                if packet.Jwt == jwt {
                    flag = false
                    break
                } 
            }

            // It's not existed
            if flag {
                // Get the JWT Payload
                payload := extractJWTPayload(jwt)

                // RawURLDecoding the JWT Payload
                decodePayload, err := decodePayloadToJSON(payload)
                if err != nil {
                    return err
                }

                // Switch map[string]interface{} to byteSlice
                jsonDecodePayload, _ := json.MarshalIndent(decodePayload, "", "  ")

                if decodePayload["exp"] != nil {
                    // Get the exp timestamp
                    exp := int64(decodePayload["exp"].(float64))
                    
                    // Switch exp timestamp format
                    newExpTime := expTimeCovert(exp)

                    p.Packets = append(p.Packets, Packet{
                        FileName:      fileName,
                        Host:          packetHost,
                        ArrivalTime:   NewArrivalTime,
                        ExpTime:       newExpTime,
                        Jwt:           jwt,
                        DecodePayload: string(jsonDecodePayload),
                    })
                } else {
                    p.Packets = append(p.Packets, Packet{
                        FileName:      fileName,
                        Host:          packetHost,
                        ArrivalTime:   NewArrivalTime,
                        ExpTime:       "null",
                        Jwt:           jwt,
                        DecodePayload: string(jsonDecodePayload),
                    })
                }
            }
        }
    }

    return nil
}

func main() {
    defer func() {
        fmt.Println("Process was Finished!")
        os.Exit(0)
    }()

    dataInfo := DataInfo{}
    // Read the data directory
    categories, _ := os.ReadDir(dataPath)
    for _, category := range categories {
        // Get the category directory path
        categoryPath := filepath.Join(dataPath, category.Name())
        ips, _ := os.ReadDir(categoryPath)
        for _, ip := range ips {
            packetInfo := &PacketInfo{} 
            packetInfo.IP = ip.Name()

            // Get the ip directory path
            ipPath := filepath.Join(categoryPath, ip.Name())
            pacpFiles, _ := os.ReadDir(ipPath)
            for _, file := range pacpFiles {
                pcapFile = filepath.Join(ipPath, file.Name())
                handle, err = pcap.OpenOffline(pcapFile)
                if err != nil {
                    log.Fatal(err)
                }
                
                defer handle.Close()
                
                packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
                for packet := range packetSource.Packets() {
                    err := packetInfo.printPacketInfo(packet, file.Name())
                    if err != nil {
                        fmt.Println(ip.Name(), file.Name(), err)
                        continue
                    }
                }
            }

            dataInfo.Data = append(dataInfo.Data, *packetInfo)
        } 
    }

    byteSlice, _ := json.MarshalIndent(dataInfo, "", "    ")
    err := os.WriteFile(filepath.Join(outputPath, "result.json"), byteSlice, 0644)
    if err != nil {
        fmt.Println("The file can't be written ")
    }
}
