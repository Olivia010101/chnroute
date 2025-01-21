import sys
from ipaddress import IPv4Network, IPv6Network, collapse_addresses, ip_network


def classify_network(cidr_str):

    cidr = cidr_str.strip()
    for version in (4, 6):
        try:
            if version == 4:
                return IPv4Network(cidr, strict=False), version
            else:
                return IPv6Network(cidr, strict=False), version
        except ValueError:
            continue
    return None, None


def merge_cidrs(cidr_strings):
    """合并IPv4/IPv6混合CIDR地址"""
    ipv4_networks = []
    ipv6_networks = []

    for cidr in cidr_strings:
        net, version = classify_network(cidr)
        if not net:
            # print(f"警告：忽略无效CIDR格式 '{cidr.strip()}'", file=sys.stderr)
            continue

        if version == 4:
            ipv4_networks.append(net)
        else:
            ipv6_networks.append(net)

    merged_address = []
    ipv4_address = []
    ipv6_address = []
    if ipv4_networks:
        ipv4_address = list(collapse_addresses(ipv4_networks))
        merged_address += ipv4_address
    if ipv6_networks:
        ipv6_address = list(collapse_addresses(ipv6_networks))
        merged_address += ipv6_address

    ipv4_address = sorted(ipv4_address, key=lambda x: x.network_address)
    ipv6_address = sorted(ipv6_address, key=lambda x: x.network_address)
    merged_address = sorted(
        merged_address, key=lambda x: (isinstance(x, IPv6Network), x.network_address)
    )

    return (
        [str(address) for address in ipv4_address],
        [str(address) for address in ipv6_address],
        [str(address) for address in merged_address],
    )


def main():
    merged_output_file = "chroute.txt"
    ipv4_output_file = "chroute_ipv4.txt"
    ipv6_output_file = "chroute_ipv6.txt"


    if len(sys.argv) > 1:

        with open(sys.argv[1], "r") as f:
            cidr_strings = f.readlines()

        if len(sys.argv) > 2:
            merged_output_file = sys.argv[2]
    else:
        # 从标准输入读取
        cidr_strings = sys.stdin.readlines()

    # 执行合并
    ipv4_address, ipv6_address, merged_address = merge_cidrs(cidr_strings)

    # 写入输出文件
    with open(merged_output_file, "w") as f:
        f.write("\n".join(merged_address))
    with open(ipv4_output_file, "w") as f:
        f.write("\n".join(ipv4_address))
    with open(ipv6_output_file, "w") as f:
        f.write("\n".join(ipv6_address))

    print(f"合并完成，结果已保存至 {merged_output_file}", file=sys.stderr)


if __name__ == "__main__":
    main()
