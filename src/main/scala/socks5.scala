package firesocks.socks5

class Greeting(
  val auth_methods: Array[AuthMethod]
)

sealed abstract class AuthMethod
case object NoAuth extends AuthMethod
case object GssapiAuth extends AuthMethod
case object UserPassAuth extends AuthMethod
case class IanaAuth(val method: Byte) extends AuthMethod
case class PrivAuth(val value: Byte) extends AuthMethod

class GreetingResponse(
  val auth_method: Option[AuthMethod]
)

sealed abstract class ConnectionRequest(addr: Address, port: Int)
case class TcpConnRequest(addr: Address, port: Int) extends ConnectionRequest(addr, port)
case class BindRequest(addr: Address, port: Int) extends ConnectionRequest(addr, port)
case class UdpPortRequest(addr: Address, port: Int) extends ConnectionRequest(addr, port)

sealed abstract class Address(val bytes: Array[Byte])
case class Ipv4Address(val bytes: Array[Byte]) extends Address(bytes)
case class Ipv6Address(val bytes: Array[Byte]) extends Address(bytes)
case class DomainNameAddress(val bytes: Array[Byte]) extends Address(bytes)

class ConnectionResponse(
  val status: ConnectionStatus,
  val addr: Address,
  val port: Int
)

sealed abstract class ConnectionStatus
case object RequestGranted extends ConnectionStatus
case object GeneralFailure extends ConnectionStatus
case object ConnectionNotAllowed extends ConnectionStatus
case object NetworkUnreachable extends ConnectionStatus
case object HostUnreachable extends ConnectionStatus
case object ConnectionRefused extends ConnectionStatus
case object TtlExpired extends ConnectionStatus
case object ProtocolError extends ConnectionStatus
case object UnsupportedAddressType extends ConnectionStatus

trait Read[T] {
  def read(from: InputStream): Option[T]
}

trait Write[T] {
  def write(to: OutputStream, data: T)
}

implicit object ReadImpl_Greeting extends Read[Greeting] {
  override def read(from: InputStream) = {
    val version = from.read()
    if (version == -1 || version != 5) return None
    val nmet = from.read()
    if (nmet == -1) return None
    val methods = new Array[AuthMethod](nmet)
    for (i <- 1 to nmet) {
      implicitly[Read[AuthMethod]].read(from) match {
        None => return None
        Some(m) => methods(i - 1) = m
      }
    }
    Some(new Greeting(methods))
  }
}

implicit object WriteImpl_Greeting extends Write[Greeting] {
  override def write(to: OutputStream, greeting: Greeting) {
    to.write(0x05)
    to.write(greeting.auth_methods.length)
    for (i <- 0 to ((greeting.auth_methods.length & 0xFF) - 1)) {
      implicitly[Write[AuthMethod]].write(to, greeting.auth_methods(i))
    }
  }
}

implicit object ReadImpl_AuthMethod extends Read[AuthMethod] {
  override def read(from: InputStream) = {
    from.read() match {
      case -1 => None
      case 0x00 => Some(NoAuth)
      case 0x01 => Some(GssapiAuth)
      case 0x02 => Some(UserPassAuth)
      case m if 0x03 to 0x7F contains m => Some(IanaAuth(m))
      case m if 0x80 to 0xFE contains m => Some(PrivAuth(m))
      case _ => None
    }
  }
}

implicit object WriteImpl_AuthMethod extends Write[AuthMethod] {
  override def write(to: OutputStream, auth_method: AuthMethod) {
    to.write(auth_method match {
      case NoAuth => 0x00
      case GssapiAuth => 0x01
      case UserPassAuth => 0x02
      case IanaAuth(m) => m
      case PrivAuth(m) => m
    }
  }
}

implicit object ReadImpl_GreetingResponse extends Read[GreetingResponse] {
  override def read(from: InputStream) = {
    val version = from.read()
    if (version == -1 || version != 5) return None
    from.read() match {
      case -1 => None
      case 0xFF => Some(new GreetingResponse(None))
      case met => implicitly[Read[AuthMethod]].read(from).map(am => new GreetingResponse(Some(am)))
    }
  }
}

implicit object WriteImpl_GreetingResponse extends Write[GreetingResponse] {
  override def write(to: OutputStream, res: GreetingResponse) {
    to.write(0x05)
    res.auth_method match {
      case Some(am) => implicitly[Write[AuthMethod]].write(to, am)
      case None => to.write(0xFF)
    }
  }
}

implicit object ReadImpl_ConnectionRequest extends Read[ConnectionRequest] {
  override def read(from: InputStream) = {
    val version = from.read()
    if (version == -1 || version != 5) return None
    val cmd = from.read()
    if (cmd == -1) return None
    if (from.read() != 0x00) return None
    implicitly[Read[Address]].read(from) match {
      case None => None
      case Some(addr) =>
        val port = readPort(from)
        if (port == -1) return None
        cmd match {
          case 0x01 => Some(TcpConnRequest(addr, port)
          case 0x02 => Some(BindRequest(addr, port))
          case 0x03 => Some(UdpPortRequest(addr, port))
          case _ => None
        }
    }
  }

  private def readPort(from: InputStream) = {
    val high = from.read()
    val low = from.read()
    if (high == -1 || low == -1) return -1
    (high << 8) | low
  }
}

implicit object WriteImpl_ConnectionRequest extends Write[ConnectionRequest] {
  override def write(to: OutputStream, req: ConnectionRequest) {
    to.write(0x05)
    to.write(req match {
      case TcpConnRequest(_, _) => 0x01
      case BindRequest(_, _) => 0x02
      case UdpPortRequest(_, _) => 0x03
    })
    to.write(0x00)
    implicitly[Write[Address]].write(to, req.addr)
    writePort(to, req.port)
  }

  private def writePort(to: OutputStream, port: Int) {
    to.write((port & 0xFF00) >> 8)
    to.write(port & 0x00FF)
  }
}

implicit object ReadImpl_Address extends Read[Address] {
  override def read(from: InputStream) = from.read() match {
    case -1 => None
    case 0x01 => readNBytes(from, 4) map Ipv4Address
    case 0x03 => readVarBytes(from) map DomainNameAddress
    case 0x04 => readNBytes(from, 16) map Ipv6Address
    case _ => None
  }

  private def readNBytes(from: InputStream, n: Int) = {
    val bytes = new Array[Byte](n)
    var r = 0
    while (r != n) {
      val ret = from.read(bytes, r, n - r)
      if (ret == -1) return None
      r += ret
    }
    Some(bytes)
  }
  private def readVarBytes(from: InputStream) = {
    val n = from.read()
    if (n == -1) return None
    readNBytes(from, n)
  }
}

implicit object WriteImpl_Address extends Write[Address] {
  override def write(to: OutputStreaml, addr: Address) {
    to.write(addr match {
      case Ipv4Address(_) => 0x01
      case DomainNameAddress(_) => 0x03
      case Ipv6Address(_) => 0x04
    })
    to.write(addr.bytes)
  }
}

implicit object ReadImpl_ConnectionResponse extends Read[ConnectionResponse] {
  override def read(from: InputStream) = try {
    val version = from.read()
    if (version == -1 || version != 0x05) return None
    val status = implicitly[Read[ConnectionStatus]].read(from).get
    if (from.read != 0x00) return None
    val addr = implicitly[Read[Address]].read(from).get
    val port = readPort(from)
    Some(new ConnectionResponse(status, addr, port))
  }
  catch {
    case _: java.util.NoSuchElementException => None
  }

  private def readPort(from: InputStream) = {
    val high = from.read()
    val low = from.read()
    if (high == -1 || low == -1) return -1
    (high << 8) | low
  }
}

implicit object WriteImpl_ConnectionResponse extends Write[ConnectionResponse] {
  override def write(to: OutputStream, res: ConnectionResponse) {
    to.write(0x05)
    implicitly[Write[ConnectionStatus]].write(to, res.status)
    to.write(0x00)
    implicitly[Write[Address]].write(to, res.addr)
    writePort(to, res.port)
  }

  private def writePort(to: OutputStream, port: Int) {
    to.write((port & 0xFF00) >> 8)
    to.write(port & 0x00FF)
  }
}
