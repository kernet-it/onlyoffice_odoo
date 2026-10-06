import io
import json
import re
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

import requests

from odoo.tests import HttpCase, new_test_user, tagged
from odoo.tests.common import JsonRpcException
from odoo.tools import mute_logger

from odoo.addons.onlyoffice_odoo.utils import config_constants, config_utils, jwt_utils


@tagged("-at_install", "post_install")
class TestOnlyofficeControllers(HttpCase):
    internal_secret = "onlyoffice-test-internal-signing-secret"
    secret = "onlyoffice-test-document-server-secret"
    original_content = b"original office document"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.editor = new_test_user(cls.env, "onlyoffice_test_editor", groups="base.group_user")
        cls.other_user = new_test_user(cls.env, "onlyoffice_test_other", groups="base.group_user")
        cls.attachment = (
            cls.env["ir.attachment"]
            .with_user(cls.editor)
            .create(
                {
                    "name": "report.docx",
                    "raw": cls.original_content,
                    "mimetype": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "public": True,
                    "access_token": "onlyoffice-test-attachment-access-token",
                }
            )
        )
        cls.private_attachment = cls.attachment.copy({"public": False, "name": "private.docx"})
        cls.readonly_attachment = cls.env["ir.attachment"].create(
            {
                "name": "readonly.docx",
                "raw": cls.original_content,
                "mimetype": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "res_model": "res.partner",
                "res_id": cls.editor.partner_id.id,
            }
        )
        params = cls.env["ir.config_parameter"]
        params.set_param(config_constants.INTERNAL_JWT_SECRET, cls.internal_secret)
        config_utils.set_doc_server_public_url(cls.env, "https://docs.example/")
        config_utils.set_doc_server_inner_url(cls.env, "http://docs.internal/")
        config_utils.set_doc_server_odoo_url(cls.env, cls.base_url())
        config_utils.set_jwt_header(cls.env, "AuthorizationJWT")
        config_utils.set_jwt_secret(cls.env, cls.secret)

    def setUp(self):
        super().setUp()
        self.authenticate(self.editor.login, self.editor.login)

    def _security_token(self, user=None):
        return jwt_utils.encode_payload(self.env, {"id": (user or self.editor).id}, self.internal_secret)

    def _callback(self, body, sign=True, security_token=None, attachment=None, access_token=None):
        body = dict(body)
        if sign:
            body["token"] = jwt_utils.encode_payload(self.env, {"payload": dict(body)}, self.secret)
        params = {"oo_security_token": security_token or self._security_token()}
        if access_token is not None:
            params["access_token"] = access_token
        return self.url_open(
            f"/onlyoffice/editor/callback/{(attachment or self.attachment).id}",
            params=params,
            json=body,
        )

    def _rendered_config(self, response):
        self.assertEqual(response.status_code, 200)
        match = re.search(r"var config = (.*?);\s", response.text, re.DOTALL)
        self.assertIsNotNone(match, response.text[:500])
        return json.loads(match.group(1))

    def test_editor_configuration_and_signed_urls(self):
        values = self.make_jsonrpc_request(
            "/onlyoffice/editor/get_config",
            {"attachment_id": self.attachment.id, "access_token": self.attachment.access_token},
        )
        config = values["editorConfig"]
        self.assertEqual(config["documentType"], "word")
        self.assertEqual(config["type"], "desktop")
        self.assertEqual(config["document"]["title"], self.attachment.name)
        self.assertEqual(config["document"]["key"], f"{self.attachment.id}{self.attachment.checksum}")
        self.assertEqual(config["editorConfig"]["mode"], "edit")
        self.assertTrue(config["document"]["permissions"]["edit"])
        self.assertEqual(config["editorConfig"]["user"]["id"], str(self.editor.id))
        query = parse_qs(urlparse(config["document"]["url"]).query)
        self.assertEqual(query["access_token"], [self.attachment.access_token])
        self.assertEqual(
            jwt_utils.decode_token(self.env, query["oo_security_token"][0], self.internal_secret)["id"], self.editor.id
        )
        signed = jwt_utils.decode_token(self.env, config["token"], self.secret)
        self.assertEqual(signed["document"], config["document"])
        self.assertIn(f"/onlyoffice/editor/callback/{self.attachment.id}", config["editorConfig"]["callbackUrl"])
        self.assertTrue(values["docApiJS"].startswith("https://docs.example/web-apps/"))

    def test_mobile_view_configuration_without_server_jwt(self):
        config_utils.set_jwt_secret(self.env, False)
        self.attachment.name = "legacy.doc"
        values = self.make_jsonrpc_request(
            "/onlyoffice/editor/get_config", {"attachment_id": self.attachment.id}, headers={"User-Agent": "Android"}
        )
        config = values["editorConfig"]
        self.assertEqual(config["type"], "mobile")
        self.assertEqual(config["editorConfig"]["mode"], "view")
        self.assertFalse(config["document"]["permissions"]["edit"])
        self.assertNotIn("callbackUrl", config["editorConfig"])
        self.assertNotIn("token", config)

    @mute_logger("odoo.http", "odoo.addons.onlyoffice_odoo.controllers.controllers")
    def test_unsupported_file_is_rejected(self):
        self.attachment.name = "unsupported.unknown"
        with self.assertRaises(JsonRpcException):
            self.make_jsonrpc_request("/onlyoffice/editor/get_config", {"attachment_id": self.attachment.id})

    def test_validation_file_and_missing_attachment(self):
        response = self.url_open("/onlyoffice/file/content/test.txt")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"test")
        self.assertEqual(response.headers["Content-Type"], "text/plain")
        missing_id = self.attachment.id
        self.attachment.unlink()
        self.assertEqual(self.url_open(f"/onlyoffice/editor/{missing_id}").status_code, 404)

    def test_editor_render_preserves_permissions_and_filters_title(self):
        self.attachment.name = "report<script>.docx"
        config = self._rendered_config(self.url_open(f"/onlyoffice/editor/{self.attachment.id}"))
        self.assertEqual(config["document"]["title"], "reportscript.docx")
        self.assertEqual(config["editorConfig"]["mode"], "edit")
        self.assertTrue(config["document"]["permissions"]["edit"])

    def test_readonly_attachment_editor_omits_callback(self):
        config = self._rendered_config(self.url_open(f"/onlyoffice/editor/{self.readonly_attachment.id}"))
        self.assertEqual(config["editorConfig"]["mode"], "view")
        self.assertFalse(config["document"]["permissions"]["edit"])
        self.assertNotIn("callbackUrl", config["editorConfig"])

    def test_preview_local_and_external_urls(self):
        for url in (
            f"/onlyoffice/file/content/{self.attachment.id}",
            "https://files.example/report.docx",
            "files/report.docx",
        ):
            with self.subTest(url=url):
                config = self._rendered_config(
                    self.url_open("/onlyoffice/preview", params={"url": url, "title": "report.docx"})
                )
                self.assertEqual(config["type"], "embedded")
                self.assertEqual(config["editorConfig"]["mode"], "view")
                self.assertFalse(config["document"]["permissions"]["edit"])
                if url.startswith("/onlyoffice/file/content/"):
                    query = parse_qs(urlparse(config["document"]["url"]).query)
                    self.assertEqual(
                        jwt_utils.decode_token(self.env, query["oo_security_token"][0], self.internal_secret)["id"],
                        self.editor.id,
                    )
                elif url.startswith("https://"):
                    self.assertEqual(config["document"]["url"], url)
                else:
                    self.assertEqual(config["document"]["url"], self.base_url() + "/" + url)
                signed = jwt_utils.decode_token(self.env, config["token"], self.secret)
                self.assertEqual(signed["document"], config["document"])

    def test_file_content_requires_valid_server_signature(self):
        server_token = jwt_utils.encode_payload(self.env, {"document": self.attachment.id}, self.secret)
        response = self.url_open(
            f"/onlyoffice/file/content/{self.attachment.id}",
            params={"oo_security_token": self._security_token(), "access_token": self.attachment.access_token},
            headers={"AuthorizationJWT": "Bearer " + server_token},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, self.original_content)
        self.assertIn("attachment", response.headers["Content-Disposition"])

    @mute_logger("odoo.http", "odoo.addons.onlyoffice_odoo.controllers.controllers")
    def test_content_missing_server_token_is_rejected(self):
        response = self.url_open(
            f"/onlyoffice/file/content/{self.attachment.id}", params={"oo_security_token": self._security_token()}
        )
        self.assertEqual(response.status_code, 500)
        self.assertNotEqual(response.content, self.original_content)

    @mute_logger("odoo.http", "odoo.addons.onlyoffice_odoo.controllers.controllers")
    def test_content_wrong_server_signature_is_rejected(self):
        forged = jwt_utils.encode_payload(
            self.env, {"document": self.attachment.id}, "onlyoffice-test-wrong-signing-secret"
        )
        response = self.url_open(
            f"/onlyoffice/file/content/{self.attachment.id}",
            params={"oo_security_token": self._security_token()},
            headers={"AuthorizationJWT": "Bearer " + forged},
        )
        self.assertEqual(response.status_code, 500)
        self.assertNotEqual(response.content, self.original_content)

    @mute_logger("odoo.http", "odoo.addons.onlyoffice_odoo.controllers.controllers")
    def test_other_user_cannot_download_private_attachment(self):
        server_token = jwt_utils.encode_payload(self.env, {"document": self.private_attachment.id}, self.secret)
        owner_response = self.url_open(
            f"/onlyoffice/file/content/{self.private_attachment.id}",
            params={"oo_security_token": self._security_token()},
            headers={"AuthorizationJWT": "Bearer " + server_token},
        )
        self.assertEqual(owner_response.status_code, 200)
        self.assertEqual(owner_response.content, self.original_content)
        self.authenticate(self.other_user.login, self.other_user.login)
        response = self.url_open(
            f"/onlyoffice/file/content/{self.private_attachment.id}",
            params={"oo_security_token": self._security_token(self.other_user)},
            headers={"AuthorizationJWT": "Bearer " + server_token},
        )
        self.assertEqual(response.status_code, 403)
        self.assertNotEqual(response.content, self.original_content)

    @mute_logger("odoo.http", "odoo.addons.onlyoffice_odoo.controllers.controllers")
    def test_wrong_access_token_is_rejected(self):
        server_token = jwt_utils.encode_payload(self.env, {"document": self.attachment.id}, self.secret)
        response = self.url_open(
            f"/onlyoffice/file/content/{self.attachment.id}",
            params={"oo_security_token": self._security_token(), "access_token": "wrong-attachment-token"},
            headers={"AuthorizationJWT": "Bearer " + server_token},
        )
        self.assertEqual(response.status_code, 403)
        self.assertNotEqual(response.content, self.original_content)
        with patch("odoo.addons.onlyoffice_odoo.controllers.controllers.urlopen") as urlopen:
            response = self._callback(
                {"status": 2, "url": "https://docs.example/files/result.docx"}, access_token="wrong-attachment-token"
            )
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["error"], 1)
        urlopen.assert_not_called()
        self.attachment.invalidate_recordset()
        self.assertEqual(self.attachment.raw, self.original_content)

    def test_callback_saves_downloaded_content(self):
        updated = b"edited office document"
        with patch(
            "odoo.addons.onlyoffice_odoo.controllers.controllers.urlopen", return_value=io.BytesIO(updated)
        ) as urlopen:
            response = self._callback({"status": 2, "url": "https://docs.example/files/result.docx"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"error": 0})
        self.attachment.invalidate_recordset()
        self.assertEqual(self.attachment.raw, updated)
        self.assertEqual(urlopen.call_args.args[0], "http://docs.internal/files/result.docx")
        self.assertEqual(urlopen.call_args.kwargs, {"timeout": 120, "context": None})

    def test_callback_non_save_status_does_not_download(self):
        with patch("odoo.addons.onlyoffice_odoo.controllers.controllers.urlopen") as urlopen:
            for status in (1, 4):
                with self.subTest(status=status):
                    response = self._callback({"status": status})
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.json(), {"error": 0})
        urlopen.assert_not_called()
        self.attachment.invalidate_recordset()
        self.assertEqual(self.attachment.raw, self.original_content)

    @mute_logger("odoo.addons.onlyoffice_odoo.controllers.controllers")
    def test_other_user_callback_cannot_modify_private_attachment(self):
        self.authenticate(self.other_user.login, self.other_user.login)
        with patch(
            "odoo.addons.onlyoffice_odoo.controllers.controllers.urlopen", return_value=io.BytesIO(b"unauthorized edit")
        ):
            response = self._callback(
                {"status": 2, "url": "https://docs.example/files/result.docx"},
                security_token=self._security_token(self.other_user),
                attachment=self.private_attachment,
            )
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["error"], 1)
        self.private_attachment.invalidate_recordset()
        self.assertEqual(self.private_attachment.raw, self.original_content)

    @mute_logger("odoo.addons.onlyoffice_odoo.controllers.controllers")
    def test_callback_rejects_missing_and_wrong_signatures(self):
        forged = jwt_utils.encode_payload(self.env, {"id": self.editor.id}, "onlyoffice-test-wrong-signing-secret")
        with patch("odoo.addons.onlyoffice_odoo.controllers.controllers.urlopen") as urlopen:
            responses = [
                self.url_open(f"/onlyoffice/editor/callback/{self.attachment.id}", json={"status": 2}),
                self._callback({"status": 2}, security_token=forged),
                self._callback({"status": 2}, sign=False),
            ]
        for response in responses:
            self.assertEqual(response.status_code, 500)
            self.assertEqual(response.json()["error"], 1)
        urlopen.assert_not_called()
        self.attachment.invalidate_recordset()
        self.assertEqual(self.attachment.raw, self.original_content)

    def test_form_locales_normalization(self):
        responses = [
            [{"code": "en", "name": "English"}, {"code": "es"}],
            {"unexpected": "response"},
        ]
        with patch(
            "odoo.addons.onlyoffice_odoo.controllers.controllers.requests.get",
            side_effect=[Mock(json=Mock(return_value=response)) for response in responses],
        ) as get:
            self.assertEqual(
                self.make_jsonrpc_request("/onlyoffice/oforms/locales"),
                {"data": [{"code": "en", "name": "English"}, {"code": "es", "name": "es"}]},
            )
            self.assertEqual(self.make_jsonrpc_request("/onlyoffice/oforms/locales"), {"data": []})
        self.assertEqual(get.call_args.args[0], "https://oforms.onlyoffice.com/dashboard/api/i18n/locales")
        self.assertEqual(get.call_args.kwargs["timeout"], 20)

    def test_form_category_localization_and_fallback(self):
        response = {
            "data": [
                {
                    "id": 10,
                    "attributes": {
                        "name": "Default",
                        "categoryId": 3,
                        "categoryTitle": "business",
                        "localizations": {
                            "data": [{"attributes": {"locale": "es", "name": "Local", "categorie": "Local category"}}]
                        },
                    },
                },
                {"id": 11, "attributes": {"name": "Fallback", "categorie": "Fallback category"}},
            ]
        }
        with patch(
            "odoo.addons.onlyoffice_odoo.controllers.controllers.requests.get",
            return_value=Mock(json=Mock(return_value=response)),
        ) as get:
            categories = self.make_jsonrpc_request("/onlyoffice/oforms/category-types", {"locale": "es"})
            self.assertEqual(categories["data"][0], {"id": 10, "categoryId": 3, "name": "Local", "type": "business"})
            self.assertEqual(categories["data"][1]["name"], "Fallback")
            subcategories = self.make_jsonrpc_request(
                "/onlyoffice/oforms/subcategories", {"category_type": "categorie", "locale": "es"}
            )
            self.assertEqual(
                subcategories,
                {
                    "data": [
                        {"id": 10, "name": "Local category", "category_type": "categories"},
                        {"id": 11, "name": "Fallback category", "category_type": "categories"},
                    ]
                },
            )
            self.assertEqual(get.call_args.args[0], "https://oforms.onlyoffice.com/dashboard/api/categories")
            self.assertEqual(get.call_args.kwargs["params"], {"populate": "*", "locale": "es"})
            calls = get.call_count
            self.assertEqual(
                self.make_jsonrpc_request("/onlyoffice/oforms/subcategories", {"category_type": "invalid"}),
                {"data": []},
            )
            self.assertEqual(get.call_count, calls)

    def test_form_search_filter_precedence_and_defaults(self):
        response = {"data": [{"id": 7}], "meta": {"pagination": {"total": 1}}}
        with patch(
            "odoo.addons.onlyoffice_odoo.controllers.controllers.requests.get",
            return_value=Mock(json=Mock(return_value=response)),
        ) as get:
            self.assertEqual(self.make_jsonrpc_request("/onlyoffice/oforms"), response)
            defaults = get.call_args.kwargs["params"]
            self.assertEqual(defaults["filters[form_exts][ext][$eq]"], "pdf")
            self.assertEqual(defaults["pagination[page]"], 1)
            self.assertEqual(defaults["pagination[pageSize]"], 12)
            filters = {"filters[categories][$eq]": 3, "filters[types][$eq]": 4, "filters[compilations][$eq]": 5}
            for source, target in [("categories", "categories"), ("types", "types"), ("compilations", "compilations")]:
                params = {
                    "type": "docx",
                    "locale": "es",
                    "pagination[page]": 2,
                    "pagination[pageSize]": 5,
                    "filters[name_form][$containsi]": "invoice",
                    **filters,
                }
                self.assertEqual(self.make_jsonrpc_request("/onlyoffice/oforms", {"params": params}), response)
                sent = get.call_args.kwargs["params"]
                self.assertEqual(sent[f"filters[{target}][id][$eq]"], filters.pop(f"filters[{source}][$eq]"))
                self.assertEqual(sent["filters[name_form][$containsi]"], "invoice")
                self.assertEqual(sent["filters[form_exts][ext][$eq]"], "docx")
                self.assertEqual(sent["populate[file_oform][filters][url][$endsWith]"], ".docx")
                self.assertEqual(sent["locale"], "es")
                self.assertEqual(sent["pagination[page]"], 2)
                self.assertEqual(sent["pagination[pageSize]"], 5)
            self.assertEqual(get.call_args.args[0], "https://cmsoforms.onlyoffice.com/api/oforms")

    @mute_logger("odoo.http", "odoo.addons.onlyoffice_odoo.controllers.controllers")
    def test_form_api_http_error_is_reported(self):
        with (
            patch(
                "odoo.addons.onlyoffice_odoo.controllers.controllers.requests.get",
                return_value=Mock(raise_for_status=Mock(side_effect=requests.HTTPError("service unavailable"))),
            ),
            self.assertRaises(JsonRpcException),
        ):
            self.make_jsonrpc_request("/onlyoffice/oforms/locales")

    @mute_logger("odoo.http", "odoo.addons.onlyoffice_odoo.controllers.controllers")
    def test_form_api_connection_error_is_reported(self):
        with (
            patch(
                "odoo.addons.onlyoffice_odoo.controllers.controllers.requests.get",
                side_effect=requests.ConnectionError("unreachable"),
            ),
            self.assertRaises(JsonRpcException),
        ):
            self.make_jsonrpc_request("/onlyoffice/oforms/locales")
