import datetime
import io
import zipfile

import jwt

from odoo.tests import TransactionCase

from odoo.addons.onlyoffice_odoo.utils import (
    config_constants,
    config_utils,
    file_utils,
    format_utils,
    jwt_utils,
    url_utils,
)


class TestOnlyofficeUtils(TransactionCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.secret = "onlyoffice-test-document-server-secret"
        cls.env["ir.config_parameter"].set_param(config_constants.DOC_SERVER_JWT_SECRET, cls.secret)

    def test_filename_parts(self):
        self.assertEqual(file_utils.get_file_title_without_ext("quarter.1.DOCX"), "quarter.1")
        self.assertEqual(file_utils.get_file_name_without_ext("quarter.1.DOCX"), "quarter.1")
        self.assertEqual(file_utils.get_file_ext("quarter.1.DOCX"), "docx")

    def test_format_capabilities(self):
        cases = [
            ("letter.DOCX", "word", True, True, False),
            ("sheet.xlsx", "cell", True, True, False),
            ("slides.pptx", "slide", True, True, False),
            ("legacy.doc", "word", True, False, False),
            ("form.pdf", "pdf", True, True, True),
            ("unknown.unsupported", None, False, False, False),
        ]
        for name, file_type, view, edit, fill in cases:
            with self.subTest(name=name):
                self.assertEqual(file_utils.get_file_type(name), file_type)
                self.assertEqual(file_utils.can_view(name), view)
                self.assertEqual(file_utils.can_edit(name), edit)
                self.assertEqual(file_utils.can_fill_form(name), fill)

    def test_mime_types(self):
        expected = {
            "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "pdf": "application/pdf",
            "unknown": None,
        }
        for extension, mimetype in expected.items():
            with self.subTest(extension=extension):
                self.assertEqual(file_utils.get_mime_by_ext(extension), mimetype)

    def test_default_templates_and_locale_fallback(self):
        spanish = file_utils.get_default_file_template("es", "docx")
        self.assertEqual(file_utils.get_default_file_template("es_ES", "docx"), spanish)
        self.assertEqual(file_utils.get_default_file_template("es_MX", "docx"), spanish)
        self.assertEqual(
            file_utils.get_default_file_template("unknown_XX", "docx"),
            file_utils.get_default_file_template("default", "docx"),
        )
        for extension, member in [
            ("docx", "word/document.xml"),
            ("xlsx", "xl/workbook.xml"),
            ("pptx", "ppt/presentation.xml"),
        ]:
            with self.subTest(extension=extension):
                content = file_utils.get_default_file_template("en", extension)
                with zipfile.ZipFile(io.BytesIO(content)) as archive:
                    self.assertIn(member, archive.namelist())
        self.assertTrue(file_utils.get_default_file_template("en", "pdf").startswith(b"%PDF"))

    def test_format_defaults(self):
        document_format = format_utils.Format("custom", "word")
        self.assertEqual(document_format.actions, [])
        self.assertEqual(document_format.convert, [])
        self.assertEqual(document_format.mime, [])
        other_format = format_utils.Format("other", "word")
        document_format.actions.append("view")
        self.assertEqual(other_format.actions, [])

    def test_public_url_replacement(self):
        config_utils.set_doc_server_public_url(self.env, "https://docs.example")
        config_utils.set_doc_server_inner_url(self.env, "http://docs.internal")
        self.assertEqual(
            url_utils.replace_public_url_to_internal(self.env, "https://docs.example/files/result.docx"),
            "http://docs.internal/files/result.docx",
        )
        unrelated = "https://other.example/files/result.docx"
        self.assertEqual(url_utils.replace_public_url_to_internal(self.env, unrelated), unrelated)
        config_utils.set_doc_server_inner_url(self.env, False)
        public = "https://docs.example/files/result.docx"
        self.assertEqual(url_utils.replace_public_url_to_internal(self.env, public), public)

    def test_jwt_lifetime_and_configured_secret(self):
        self.assertTrue(jwt_utils.is_jwt_enabled(self.env))
        token = jwt_utils.encode_payload(self.env, {"document": 42})
        decoded = jwt_utils.decode_token(self.env, token)
        self.assertEqual(decoded["document"], 42)
        self.assertEqual(decoded["exp"] - decoded["iat"], 24 * 60 * 60)
        config_utils.set_jwt_secret(self.env, False)
        self.assertFalse(jwt_utils.is_jwt_enabled(self.env))

    def test_jwt_explicit_secret_and_signature_rejection(self):
        internal_secret = "onlyoffice-test-internal-signing-secret"
        token = jwt_utils.encode_payload(self.env, {"id": self.env.user.id}, internal_secret)
        self.assertEqual(jwt_utils.decode_token(self.env, token, internal_secret)["id"], self.env.user.id)
        with self.assertRaises(jwt.InvalidSignatureError):
            jwt_utils.decode_token(self.env, token)

    def test_jwt_expired_token(self):
        expired = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=30)
        token = jwt.encode({"exp": expired}, self.secret, algorithm="HS256")
        with self.assertRaises(jwt.ExpiredSignatureError):
            jwt_utils.decode_token(self.env, token)
