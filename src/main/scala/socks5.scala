package firesocks.socks5

import java.io.{InputStream, OutputStream}

class Greeting(
  val auth_methods: Array[AuthMethod]
)

sealed abstract class AuthMethod
case object NoAuth extends AuthMethod
case object GssapiAuth extends AuthMethod
case object UserPassAuth extends AuthMethod
case class IanaAuth(val method: Int) extends AuthMethod
case class PrivAuth(val value: Int) extends AuthMethod

class GreetingResponse(
  val auth_method: Option[AuthMethod]
)

sealed abstract class ConnectionRequest {
  def addr: Address
  def port: Int
}
case class TcpConnRequest(override val addr: Address, override val port: Int) extends ConnectionRequest
case class BindRequest(override val addr: Address, override val port: Int) extends ConnectionRequest
case class UdpPortRequest(override val addr: Address, override val port: Int) extends ConnectionRequest

sealed abstract class Address {
  def bytes: Array[Byte]
}
case class Ipv4Address(override val bytes: Array[Byte]) extends Address
case class Ipv6Address(override val bytes: Array[Byte]) extends Address
case class DomainNameAddress(override val bytes: Array[Byte]) extends Address

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

object Socks5IO {
  def read[T: Read](from: InputStream): Option[T] =
    implicitly[Read[T]].read(from)
  def write[T: Write](to: OutputStream, data: T) {
    implicitly[Write[T]].write(to, data)
  }

  private trait Read[T] {
    def read(from: InputStream): Option[T]
  }

  private trait Write[T] {
    def write(to: OutputStream, data: T)
  }

  private implicit object ReadImpl_AuthMethod extends Read[AuthMethod] {
    override def read(from: InputStream): Option[AuthMethod] = {
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

  private implicit object WriteImpl_AuthMethod extends Write[AuthMethod] {
    override def write(to: OutputStream, auth_method: AuthMethod) {
      to.write(auth_method match {
        case NoAuth => 0x00
        case GssapiAuth => 0x01
        case UserPassAuth => 0x02
        case IanaAuth(m) => m
        case PrivAuth(m) => m
      })
    }
  }

  private implicit object ReadImpl_Greeting extends Read[Greeting] {
    override def read(from: InputStream): Option[Greeting] = {
      val version = from.read()
      if (version == -1 || version != 5) return None
      val nmet = from.read()
      if (nmet == -1) return None
      val methods = new Array[AuthMethod](nmet)
      for (i <- 1 to nmet) {
        implicitly[Read[AuthMethod]].read(from) match {
          case None => return None
          case Some(m) => methods(i - 1) = m
        }
      }
      Some(new Greeting(methods))
    }
  }

  private implicit object WriteImpl_Greeting extends Write[Greeting] {
    override def write(to: OutputStream, greeting: Greeting) {
      to.write(0x05)
      to.write(greeting.auth_methods.length)
      for (i <- 0 to ((greeting.auth_methods.length & 0xFF) - 1)) {
        implicitly[Write[AuthMethod]].write(to, greeting.auth_methods(i))
      }
    }
  }

  private implicit object ReadImpl_GreetingResponse extends Read[GreetingResponse] {
    override def read(from: InputStream): Option[GreetingResponse] = {
      val version = from.read()
      if (version == -1 || version != 5) return None
      from.read() match {
        case -1 => None
        case 0xFF => Some(new GreetingResponse(None))
        case met => implicitly[Read[AuthMethod]].read(from).map(am => new GreetingResponse(Some(am)))
      }
    }
  }

  private implicit object WriteImpl_GreetingResponse extends Write[GreetingResponse] {
    override def write(to: OutputStream, res: GreetingResponse) {
      to.write(0x05)
      res.auth_method match {
        case Some(am) => implicitly[Write[AuthMethod]].write(to, am)
        case None => to.write(0xFF)
      }
    }
  }

  private implicit object ReadImpl_Address extends Read[Address] {
    override def read(from: InputStream): Option[Address] = from.read() match {
      case -1 => None
      case 0x01 => readNBytes(from, 4) map Ipv4Address
      case 0x03 => readVarBytes(from) map DomainNameAddress
      case 0x04 => readNBytes(from, 16) map Ipv6Address
      case _ => None
    }

    private def readNBytes(from: InputStream, n: Int): Option[Array[Byte]] = {
      val bytes = new Array[Byte](n)
      var r = 0
      while (r != n) {
        val ret = from.read(bytes, r, n - r)
        if (ret == -1) return None
        r += ret
      }
      Some(bytes)
    }
    private def readVarBytes(from: InputStream): Option[Array[Byte]] = {
      val n = from.read()
      if (n == -1) return None
      readNBytes(from, n)
    }
  }

  private implicit object WriteImpl_Address extends Write[Address] {
    override def write(to: OutputStream, addr: Address) {
      to.write(addr match {
        case Ipv4Address(_) => 0x01
        case DomainNameAddress(_) => 0x03
        case Ipv6Address(_) => 0x04
      })
      to.write(addr.bytes)
    }
  }

  private implicit object ReadImpl_ConnectionStatus extends Read[ConnectionStatus] {
    override def read(from: InputStream): Option[ConnectionStatus] = from.read() match {
      case -1 => None
      case 0x00 => Some(RequestGranted)
      case 0x01 => Some(GeneralFailure)
      case 0x02 => Some(ConnectionNotAllowed)
      case 0x03 => Some(NetworkUnreachable)
      case 0x04 => Some(HostUnreachable)
      case 0x05 => Some(ConnectionRefused)
      case 0x06 => Some(TtlExpired)
      case 0x07 => Some(ProtocolError)
      case 0x08 => Some(UnsupportedAddressType)
      case _ => None
    }
  }

  private implicit object WriteImpl_ConnectionStatus extends Write[ConnectionStatus] {
    override def write(to: OutputStream, status: ConnectionStatus) {
      to.write(status match {
        case RequestGranted => 0x00
        case GeneralFailure => 0x01
        case ConnectionNotAllowed => 0x02
        case NetworkUnreachable => 0x03
        case HostUnreachable => 0x04
        case ConnectionRefused => 0x05
        case TtlExpired => 0x06
        case ProtocolError => 0x07
        case UnsupportedAddressType => 0x08
      })
    }
  }

  private implicit object ReadImpl_ConnectionRequest extends Read[ConnectionRequest] {
    override def read(from: InputStream): Option[ConnectionRequest] = {
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
            case 0x01 => Some(TcpConnRequest(addr, port))
            case 0x02 => Some(BindRequest(addr, port))
            case 0x03 => Some(UdpPortRequest(addr, port))
            case _ => None
          }
      }
    }

    private def readPort(from: InputStream): Int = {
      val high = from.read()
      val low = from.read()
      if (high == -1 || low == -1) return -1
      (high << 8) | low
    }
  }

  private implicit object WriteImpl_ConnectionRequest extends Write[ConnectionRequest] {
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

  private implicit object ReadImpl_ConnectionResponse extends Read[ConnectionResponse] {
    override def read(from: InputStream): Option[ConnectionResponse] = try {
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

    private def readPort(from: InputStream): Int = {
      val high = from.read()
      val low = from.read()
      if (high == -1 || low == -1) return -1
      (high << 8) | low
    }
  }

  private implicit object WriteImpl_ConnectionResponse extends Write[ConnectionResponse] {
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
}
