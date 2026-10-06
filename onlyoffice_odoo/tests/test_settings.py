import io
import json
from unittest.mock import Mock, patch

from odoo import fields
from odoo.exceptions import ValidationError
from odoo.tests import Form, TransactionCase

from odoo.addons.onlyoffice_odoo.utils import config_constants, config_utils, jwt_utils


class TestOnlyofficeSettings(TransactionCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.params = cls.env["ir.config_parameter"]
        cls.params.set_param("web.base.url", "https://odoo.example")
        cls.params.set_param(config_constants.INTERNAL_JWT_SECRET, "onlyoffice-test-internal-signing-secret")

    def test_connection_defaults(self):
        for key in (
            config_constants.DOC_SERVER_PUBLIC_URL,
            config_constants.DOC_SERVER_INNER_URL,
            config_constants.DOC_SERVER_ODOO_URL,
            config_constants.DOC_SERVER_JWT_HEADER,
        ):
            self.params.set_param(key, False)
        self.assertEqual(config_utils.get_doc_server_public_url(self.env), "http://documentserver/")
        self.assertEqual(config_utils.get_doc_server_inner_url(self.env), "http://documentserver/")
        self.assertEqual(config_utils.get_base_or_odoo_url(self.env), "https://odoo.example/")
        self.assertEqual(config_utils.get_jwt_header(self.env), "Authorization")

    def test_connection_storage_and_normalization(self):
        config_utils.set_doc_server_public_url(self.env, "docs.example")
        config_utils.set_doc_server_inner_url(self.env, "http://docs.internal/")
        config_utils.set_doc_server_odoo_url(self.env, "https://odoo.internal")
        config_utils.set_jwt_header(self.env, "AuthorizationJWT")
        config_utils.set_jwt_secret(self.env, "onlyoffice-test-document-server-secret")
        self.assertEqual(config_utils.get_doc_server_public_url(self.env), "http://docs.example/")
        self.assertEqual(config_utils.get_doc_server_inner_url(self.env), "http://docs.internal/")
        self.assertEqual(config_utils.get_base_or_odoo_url(self.env), "https://odoo.internal/")
        self.assertEqual(config_utils.get_jwt_header(self.env), "AuthorizationJWT")
        self.assertEqual(config_utils.get_jwt_secret(self.env), "onlyoffice-test-document-server-secret")
        config_utils.set_doc_server_public_url(self.env, False)
        self.assertEqual(config_utils.get_doc_server_public_url(self.env), "http://documentserver/")
        self.assertEqual(config_utils.get_internal_jwt_secret(self.env), "onlyoffice-test-internal-signing-secret")

    def test_demo_enable_and_disable(self):
        self.params.set_param(config_constants.DOC_SERVER_DEMO, False)
        self.params.set_param(config_constants.DOC_SERVER_DEMO_DATE, False)
        config_utils.set_demo(self.env, True)
        self.assertTrue(config_utils.get_demo(self.env))
        self.assertEqual(config_utils.get_demo_date(self.env), fields.Date.today().isoformat())
        self.assertEqual(config_utils.get_doc_server_public_url(self.env), "https://onlinedocs.docs.onlyoffice.com/")
        self.assertEqual(config_utils.get_jwt_header(self.env), "AuthorizationJWT")
        self.assertTrue(config_utils.get_jwt_secret(self.env))
        config_utils.set_demo(self.env, False)
        self.assertFalse(config_utils.get_demo(self.env))
        self.assertEqual(config_utils.get_doc_server_public_url(self.env), "http://documentserver/")
        self.assertEqual(config_utils.get_jwt_header(self.env), "Authorization")
        self.assertFalse(config_utils.get_jwt_secret(self.env))
        self.assertEqual(config_utils.get_demo_date(self.env), fields.Date.today().isoformat())

    def test_settings_save_and_read(self):
        with Form(self.env["res.config.settings"]) as form:
            form.doc_server_public_url = "https://docs.example/"
            form.doc_server_inner_url = "https://docs.internal/"
            form.doc_server_odoo_url = "https://odoo.internal/"
            form.doc_server_jwt_secret = "onlyoffice-test-document-server-secret"
            form.doc_server_jwt_header = "AuthorizationJWT"
            form.doc_server_disable_certificate = True
            form.same_tab = True
        settings = form.record
        with (
            patch("odoo.addons.onlyoffice_odoo.utils.validation_utils.urlopen", return_value=io.BytesIO(b"true")),
            patch(
                "odoo.addons.onlyoffice_odoo.utils.validation_utils.requests.post",
                side_effect=[
                    Mock(json=Mock(return_value={"error": 0})),
                    Mock(status_code=200, json=Mock(return_value={"endConvert": True})),
                ],
            ) as post,
        ):
            settings.set_values()
        self.assertEqual(post.call_count, 2)
        command = post.call_args_list[0]
        self.assertEqual(command.args[0], "https://docs.internal/coauthoring/CommandService.ashx")
        payload = json.loads(command.kwargs["data"])
        self.assertEqual(jwt_utils.decode_token(self.env, payload["token"])["c"], "version")
        self.assertFalse(command.kwargs["verify"])
        values = settings.get_values()
        self.assertEqual(values["doc_server_public_url"], "https://docs.example/")
        self.assertEqual(values["doc_server_inner_url"], "https://docs.internal/")
        self.assertEqual(values["doc_server_odoo_url"], "https://odoo.internal/")
        self.assertEqual(values["doc_server_jwt_header"], "AuthorizationJWT")
        self.assertTrue(values["same_tab"])
        self.assertTrue(values["doc_server_disable_certificate"])

    def test_settings_validation_failure_does_not_save(self):
        config_utils.set_demo(self.env, False)
        config_utils.set_doc_server_public_url(self.env, "https://existing.example/")
        settings = self.env["res.config.settings"].create(
            {"doc_server_public_url": "https://new.example/", "doc_server_odoo_url": "https://odoo.example/"}
        )
        with (
            patch("odoo.addons.onlyoffice_odoo.utils.validation_utils.urlopen", side_effect=OSError("unreachable")),
            self.assertRaises(ValidationError),
        ):
            settings.set_values()
        self.assertEqual(config_utils.get_doc_server_public_url(self.env), "https://existing.example/")

    def test_demo_settings_skip_external_validation(self):
        settings = self.env["res.config.settings"].create({"doc_server_demo": True})
        with (
            patch("odoo.addons.onlyoffice_odoo.utils.validation_utils.urlopen") as urlopen,
            patch("odoo.addons.onlyoffice_odoo.utils.validation_utils.requests.post") as post,
        ):
            settings.set_values()
        urlopen.assert_not_called()
        post.assert_not_called()
        self.assertTrue(config_utils.get_demo(self.env))

    def test_public_url_onchange_warning(self):
        settings = self.env["res.config.settings"].new({"doc_server_public_url": "https://invalid host/"})
        self.assertIn("warning", settings.onchange_doc_server_public_url())
        settings.doc_server_public_url = "https://docs.example/"
        self.assertIsNone(settings.onchange_doc_server_public_url())

    def test_client_preference_responses(self):
        config_utils.set_same_tab(self.env, True)
        config_utils.set_certificate_verify_disabled(self.env, True)
        config_utils.set_demo(self.env, True)
        model = self.env["onlyoffice.odoo"]
        self.assertEqual(json.loads(model.get_same_tab()), {"same_tab": "True"})
        self.assertEqual(json.loads(model.get_demo()), {"mode": "True", "date": config_utils.get_demo_date(self.env)})
        self.assertTrue(config_utils.get_certificate_verify_disabled(self.env))
