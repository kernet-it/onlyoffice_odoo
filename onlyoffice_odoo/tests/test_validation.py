import io
import json
import ssl
from unittest.mock import Mock, patch

import requests

from odoo.exceptions import ValidationError
from odoo.tests import TransactionCase

from odoo.addons.onlyoffice_odoo.utils import jwt_utils, validation_utils


class TestOnlyofficeValidation(TransactionCase):
    secret = "onlyoffice-test-document-server-secret"
    server = "https://docs.example/"
    base_url = "https://odoo.example/"

    def test_url_validation(self):
        for url in (False, "", "docs.example", "http://docs.example/", "https://docs.example:8443/"):
            with self.subTest(url=url):
                self.assertTrue(validation_utils.valid_url(url))
        for url in ("https://invalid host/", "ftp://docs.example/", "<script>"):
            with self.subTest(url=url):
                self.assertFalse(validation_utils.valid_url(url))

    def test_mixed_content(self):
        validation_utils.check_mixed_content(self.base_url, self.server, False)
        validation_utils.check_mixed_content("http://odoo.example/", "http://docs.example/", False)
        with self.assertRaisesRegex(ValidationError, "HTTPS"):
            validation_utils.check_mixed_content(self.base_url, "http://docs.example/", False)
        with self.assertRaisesRegex(ValidationError, "demo server"):
            validation_utils.check_mixed_content(self.base_url, "http://docs.example/", True)

    def test_healthcheck_certificate_policy(self):
        with patch(
            "odoo.addons.onlyoffice_odoo.utils.validation_utils.urlopen",
            side_effect=[io.BytesIO(b"true"), io.BytesIO(b"true")],
        ) as urlopen:
            validation_utils.check_doc_serv_url(self.server, False, False)
            validation_utils.check_doc_serv_url(self.server, False, True)
        self.assertEqual(urlopen.call_args_list[0].args[0], "https://docs.example/healthcheck")
        self.assertEqual(urlopen.call_args_list[0].kwargs, {"timeout": 30, "context": None})
        context = urlopen.call_args_list[1].kwargs["context"]
        self.assertFalse(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)

    def test_empty_healthcheck_is_rejected(self):
        with (
            patch("odoo.addons.onlyoffice_odoo.utils.validation_utils.urlopen", return_value=io.BytesIO(b"")),
            self.assertRaisesRegex(ValidationError, "returned false"),
        ):
            validation_utils.check_doc_serv_url(self.server, False, False)

    def test_unreachable_healthcheck_is_rejected(self):
        with (
            patch("odoo.addons.onlyoffice_odoo.utils.validation_utils.urlopen", side_effect=OSError("unreachable")),
            self.assertRaisesRegex(ValidationError, "cannot be reached"),
        ):
            validation_utils.check_doc_serv_url(self.server, False, False)

    def test_command_service_signed_request(self):
        with patch(
            "odoo.addons.onlyoffice_odoo.utils.validation_utils.requests.post",
            return_value=Mock(json=Mock(return_value={"error": 0})),
        ) as post:
            validation_utils.check_doc_serv_command_service(
                self.env, self.server, self.secret, "AuthorizationJWT", True, False
            )
        self.assertEqual(post.call_args.args[0], "https://docs.example/coauthoring/CommandService.ashx")
        self.assertEqual(post.call_args.kwargs["timeout"], 60)
        self.assertFalse(post.call_args.kwargs["verify"])
        body = json.loads(post.call_args.kwargs["data"])
        self.assertEqual(body["c"], "version")
        self.assertEqual(jwt_utils.decode_token(self.env, body["token"], self.secret)["c"], "version")
        header = post.call_args.kwargs["headers"]["AuthorizationJWT"]
        self.assertEqual(
            jwt_utils.decode_token(self.env, header.removeprefix("Bearer "), self.secret)["payload"], {"c": "version"}
        )

    def test_unsigned_command_and_service_errors(self):
        for error, message in [(6, "Authorization"), (4, "returned error")]:
            with (
                self.subTest(error=error),
                patch(
                    "odoo.addons.onlyoffice_odoo.utils.validation_utils.requests.post",
                    return_value=Mock(json=Mock(return_value={"error": error})),
                ) as post,
                self.assertRaisesRegex(ValidationError, message),
            ):
                validation_utils.check_doc_serv_command_service(
                    self.env, self.server, False, "Authorization", False, False
                )
            self.assertEqual(json.loads(post.call_args.kwargs["data"]), {"c": "version"})
            self.assertNotIn("Authorization", post.call_args.kwargs["headers"])

    def test_unreachable_command_service(self):
        with (
            patch(
                "odoo.addons.onlyoffice_odoo.utils.validation_utils.requests.post",
                side_effect=requests.ConnectionError("unreachable"),
            ),
            self.assertRaisesRegex(ValidationError, "CommandService"),
        ):
            validation_utils.check_doc_serv_command_service(self.env, self.server, False, "Authorization", False, False)

    def test_conversion_signed_request(self):
        source_url = self.base_url + "onlyoffice/file/content/test.txt"
        with patch(
            "odoo.addons.onlyoffice_odoo.utils.validation_utils.requests.post",
            return_value=Mock(status_code=200, json=Mock(return_value={"endConvert": True})),
        ) as post:
            result = validation_utils.convert(self.env, source_url, self.server, self.secret, "AuthorizationJWT", False)
        self.assertIsNone(result)
        body = json.loads(post.call_args.kwargs["data"])
        self.assertEqual(body["url"], source_url)
        self.assertEqual(body["filetype"], "txt")
        self.assertEqual(body["outputtype"], "txt")
        self.assertEqual(post.call_args.args[0], f"https://docs.example/converter/?shardkey={body['key']}")
        signed = jwt_utils.decode_token(self.env, body["token"], self.secret)
        self.assertEqual(signed["url"], source_url)
        header = post.call_args.kwargs["headers"]["AuthorizationJWT"].removeprefix("Bearer ")
        self.assertEqual(jwt_utils.decode_token(self.env, header, self.secret)["payload"]["key"], body["key"])
        self.assertTrue(post.call_args.kwargs["verify"])

    def test_conversion_service_errors(self):
        cases = [
            (Mock(status_code=503), "status 503"),
            (Mock(status_code=200, json=Mock(return_value={"error": -8})), "Invalid token"),
            (Mock(status_code=200, json=Mock(return_value={"error": -99})), "Undefined error code"),
        ]
        for response, message in cases:
            with (
                self.subTest(message=message),
                patch("odoo.addons.onlyoffice_odoo.utils.validation_utils.requests.post", return_value=response),
            ):
                result = validation_utils.convert(
                    self.env, "https://odoo.example/test.txt", self.server, False, "Authorization", False
                )
            self.assertIn(message, result)
        with patch(
            "odoo.addons.onlyoffice_odoo.utils.validation_utils.requests.post",
            side_effect=requests.ConnectionError("unreachable"),
        ):
            self.assertIn(
                "cannot be reached",
                validation_utils.convert(
                    self.env, "https://odoo.example/test.txt", self.server, False, "Authorization", False
                ),
            )

    def test_conversion_validation_propagates_failure(self):
        with (
            patch(
                "odoo.addons.onlyoffice_odoo.utils.validation_utils.requests.post", return_value=Mock(status_code=502)
            ),
            self.assertRaisesRegex(ValidationError, "demo server"),
        ):
            validation_utils.check_doc_serv_convert_service(
                self.env, self.server, self.base_url, False, "Authorization", False, True
            )

    def test_conversion_error_mapping(self):
        self.assertEqual(validation_utils.get_conversion_error_message(-2), "Conversion timeout error")
        self.assertEqual(validation_utils.get_conversion_error_message(-5), "Incorrect password")
        self.assertEqual(validation_utils.get_conversion_error_message(None), "Undefined error code")
