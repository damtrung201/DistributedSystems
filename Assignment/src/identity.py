# identity.py
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64


class UserIdentity:
    """Quản lý danh tính số của người dùng bằng cặp khóa不对称."""

    def __init__(self, private_key_path=None):
        if private_key_path:
            with open(private_key_path, "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(key_file.read(), password=None)
        else:
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        self.public_key = self.private_key.public_key()
        self.user_id = self._get_b64_public_key()  # user_id chính là khóa public

    def save_private_key(self, path):
        """Lưu khóa private vào file để sử dụng lại."""
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(path, "wb") as f:
            f.write(pem)

    def _get_b64_public_key(self):
        """Chuyển khóa public thành chuỗi base64 để dễ dàng chia sẻ."""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(pem).decode('utf-8')

    def sign_message(self, message: str) -> str:
        """Tạo chữ ký số cho một tin nhắn."""
        signature = self.private_key.sign(
            message.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def verify_signature(public_key_b64: str, signature_b64: str, message: str) -> bool:
        """Xác thực chữ ký của một tin nhắn bằng khóa public của người gửi."""
        try:
            public_key = serialization.load_pem_public_key(base64.b64decode(public_key_b64))
            signature = base64.b64decode(signature_b64)
            public_key.verify(
                signature,
                message.encode('utf-8'),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False