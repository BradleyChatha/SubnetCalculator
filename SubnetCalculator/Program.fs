open System
open System.Net

type CalcOp =
    Breakdown
    | Count
    | Subnet

type Args = {
    Op: CalcOp
    Ip: int
    NetCIDR: int
    SubCIDR: int
}

type IpBreakdown = {
    Network:   string
    SubNet:    string
    Host:      string
    FullNet:   string
    FullIp:    string
}

type NetworkCountBreakdown = {
    Subnets:        int
    HostsPerSubnet: int
}

type SubnetBreakdown = {
    Network:   string
    First:     string
    Last:      string
    Broadcast: string
    Next:      string option
}

type ArgResult =
    Failure of string
    | Success of Args

let (|CIDR|_|) (cidr: string) =
    match Int32.TryParse(cidr) with
    | (true, value) when value <= 32 -> Some value
    | _ -> None

let (|CalcOpParam|_|) (op: string) =
    match op with
    | "breakdown"
    | "break"
    | "b" -> Some CalcOp.Breakdown
    | "netcount"
    | "count"
    | "c" -> Some CalcOp.Count
    | "subnet"
    | "sub"
    | "s" -> Some CalcOp.Subnet
    | _ -> None

let (|IP|_|) (ip: string) =
    let mutable addr: IPAddress = null
    if IPAddress.TryParse(ip, &addr) then 
        ip.Split '.'
        |> Array.map Int32.Parse
        |> Array.reduce (fun a b -> (a <<< 8) ||| b)
        |> Some
    else 
        None

let parseArgs (argv: string []) =
    if argv.Length <> 4 then
        ArgResult.Failure($"Expected 4 arguments but only got {argv.Length}")
    else
        try
            let op = match argv.[0] with
            | CalcOpParam op -> op
            | _ -> failwith "Unknown calc operation"

            let ip = match argv.[1] with
            | IP addr -> addr
            | _ -> failwith "Bad IP Address"

            let netCidr = match argv.[2] with
            | CIDR cidr -> cidr
            | _ -> failwith "Bad network CIDR mask"

            let subCidr = match argv.[3] with
            | CIDR cidr -> cidr
            | _ -> failwith "Bad subnet CIDR mask"

            ArgResult.Success({ Args.Op = op; Ip = ip; NetCIDR = netCidr; SubCIDR = subCidr })
        with
            | _ as ex -> ArgResult.Failure(ex.Message)

let asIpString (ip: int) =
    $"{(ip &&& 0xFF000000) >>> 24}.{(ip &&& 0x00FF0000) >>> 16}.{(ip &&& 0xFF00) >>> 8}.{ip &&& 0xFF}"

let cidrToMask (cidr: int) =
    (int)(0xFFFFFFFFu >>> (32 - cidr)) // Have to do it to an unsigned number otherwise F# sign extends the number.

let getHostCidr net sub =
    let hostCidr = 32 - (net + sub)
    if hostCidr > 32 then invalidOp "Net CIDR and Subnet CIDR are over 32 bits when put together"
    hostCidr

let getIpBreakdown (ip: int, net: int, sub: int) =
    let hostCidr = getHostCidr net sub

    let netMask     = (cidrToMask net) <<< (sub + hostCidr)
    let subMask     = (cidrToMask sub) <<< (hostCidr)
    let fullNetMask = netMask ||| subMask
    let hostMask    = cidrToMask hostCidr

    let network = (asIpString (ip &&& netMask)) + $"/{net}"
    let subnet  = (asIpString (ip &&& subMask)) + $"/{sub}"
    let fullNet = (asIpString (ip &&& fullNetMask)) + $"/{net+sub}"
    let host    = (asIpString (ip &&& hostMask)) + $"/{hostCidr}"

    {
        IpBreakdown.Network = network
        SubNet              = subnet
        Host                = host
        FullNet             = fullNet
        FullIp              = (asIpString ip) + $"/{net+sub}"
    }

let getSubnetBreakdown (ip: int, net: int, sub: int) =
    let hostCidr = getHostCidr net sub
    let hostMask = cidrToMask hostCidr
    let netMask  = (cidrToMask net) <<< (sub + hostCidr)
    let subMask  = (cidrToMask sub) <<< (hostCidr)
    let netIp    = ip &&& netMask
    let subIp    = ip &&& subMask
    
    if (ip &&& (cidrToMask hostCidr)) > 0 then
        invalidOp "The provided IP is a host, not a subnet address."

    let network   = ip &&& (netIp ||| subIp)
    let first     = network + 1
    let broadcast = network ||| hostMask
    let last      = broadcast - 1
    let next      = broadcast + 1

    {
        SubnetBreakdown.Broadcast = asIpString broadcast
        First = asIpString first
        Last = asIpString last
        Network = asIpString network
        Next = if (subIp <> subMask) then Some (asIpString next) else None
    }

let getNetworkBreakdown (ip: int, net: int, sub: int) =
    let hostCidr = getHostCidr net sub

    if (ip &&& (cidrToMask hostCidr)) > 0 then
        invalidOp "The provided IP is a host, not a network address."
    elif (ip &&& ((cidrToMask sub) <<< hostCidr)) > 0 then
        invalidOp "The provided IP is a subnet, not a network address."

    let hosts   = (pown 2 hostCidr) - 2
    let subnets = pown 2 sub

    {
        NetworkCountBreakdown.HostsPerSubnet = hosts
        Subnets = subnets
    }

let runBreakdown (args: Args) =
    let info = getIpBreakdown (args.Ip, args.NetCIDR, args.SubCIDR)
    Console.WriteLine($"Breakdown of IP {info.FullIp}:")
    Console.WriteLine($"    Full Network -   {info.FullNet}")
    Console.WriteLine($"    Network      -   {info.Network}")
    Console.WriteLine($"    Subnet       -   {info.SubNet}")
    Console.WriteLine($"    Host         -   {info.Host}")
    ()

let runNetworkCountBreakdown (args: Args) =
    let info = getNetworkBreakdown (args.Ip, args.NetCIDR, args.SubCIDR)
    Console.WriteLine($"Breakdown of Network {asIpString args.Ip}/{args.NetCIDR}+{args.SubCIDR}={args.NetCIDR + args.SubCIDR}:")
    Console.WriteLine($"    Subnets      -  {info.Subnets}")
    Console.WriteLine($"    Hosts        -  {info.HostsPerSubnet}")
    ()

let runSubnetBreakdown (args: Args) =
    let info = getSubnetBreakdown (args.Ip, args.NetCIDR, args.SubCIDR)
    Console.WriteLine($"Breakdown of Subnet {asIpString args.Ip}/{args.NetCIDR}+{args.SubCIDR}={args.NetCIDR + args.SubCIDR}:")
    Console.WriteLine($"    Network      - {info.Network}/{args.NetCIDR + args.SubCIDR}")
    Console.WriteLine($"    Broadcast    - {info.Broadcast}/{args.NetCIDR + args.SubCIDR}")
    Console.WriteLine($"    First        - {info.First}/{args.NetCIDR + args.SubCIDR}")
    Console.WriteLine($"    Last         - {info.Last}/{args.NetCIDR + args.SubCIDR}")
    Console.WriteLine($"""    Next         - {info.Next |> defaultArg <| "THIS WAS THE LAST ONE"}/{args.NetCIDR + args.SubCIDR}""")
    ()

[<EntryPoint>]
let main argv =
    let args = parseArgs argv

    match args with
    | Success s ->
        match s.Op with
        | Breakdown -> runBreakdown s
        | Count -> runNetworkCountBreakdown s
        | Subnet -> runSubnetBreakdown s
        Console.ReadKey() |> ignore
        0
    | Failure f -> 
        Console.WriteLine(f)
        Console.ReadKey() |> ignore
        -1
