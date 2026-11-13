import unittest, json
from pipeline import normalize_phone, parse_date, parse_decimal, classify_bucket, select_effective_disposition

D = {
    ('motor_renewal','renewed'):{'is_terminal':True,'is_success':True},
    ('motor_renewal','callback_requested'):{'is_terminal':False,'is_success':False},
}

class NormalizationTests(unittest.TestCase):
    def test_phone_formats(self):
        for raw in ('9876543210','+91 98765 43210','09876543210','91-98765-43210','(+91) 9876543210'):
            self.assertEqual(normalize_phone(raw), '+919876543210')
    def test_invalid_phone(self):
        for raw in ('123456789','5123456789','022-2000-1234','N/A'):
            with self.assertRaises(ValueError): normalize_phone(raw)
    def test_dates_day_first_and_month_name(self):
        self.assertEqual(parse_date('2026-12-01'),'2026-12-01')
        self.assertEqual(parse_date('01/12/2026'),'2026-12-01')
        self.assertEqual(parse_date('01-Dec-2026'),'2026-12-01')
        with self.assertRaises(ValueError): parse_date('31/02/2026')
    def test_decimal_currency_and_rounding(self):
        self.assertEqual(parse_decimal('₹12,345'),'12345.00')
        self.assertEqual(parse_decimal('Rs. 12.345'),'12.35')
        with self.assertRaises(ValueError): parse_decimal('-1')
    def test_bucket_precedence(self):
        self.assertEqual(classify_bucket([],D,'motor_renewal'),'yet_to_reach_out')
        self.assertEqual(classify_bucket([{'code':'renewed','telephony_failed':False}],D,'motor_renewal'),'completed')
        self.assertEqual(classify_bucket([{'code':None,'telephony_failed':True}],D,'motor_renewal'),'in_progress_telephony_failed')
        self.assertEqual(classify_bucket([{'code':'callback_requested','telephony_failed':False}],D,'motor_renewal'),'in_progress_dialed')
        self.assertEqual(classify_bucket([{'code':None,'telephony_failed':True},{'code':None,'telephony_failed':False}],D,'motor_renewal'),'in_progress_dialed')
    def test_effective_disposition_prefers_latest_override_by_instant(self):
        def event(event_type, code, timestamp, event_id):
            return {'event_type':event_type,'workflow_id':'motor_renewal','occurred_at':timestamp,
                    'event_id':event_id,'payload_json':json.dumps({'disposition_code':code})}
        rows=[event('disposition.set','renewed','2026-10-01T10:00:00+05:30','1'),
              event('disposition.override','callback_requested','2026-10-01T10:00:00Z','2'),
              event('disposition.override','renewed','2026-10-01T14:00:00+05:30','3')]
        self.assertEqual(select_effective_disposition(rows,D),'callback_requested')
    def test_unknown_disposition_is_ignored(self):
        rows=[{'event_type':'disposition.set','workflow_id':'motor_renewal','occurred_at':'2026-10-01T10:00:00+05:30',
               'event_id':'1','payload_json':json.dumps({'disposition_code':'renewed'})},
              {'event_type':'disposition.override','workflow_id':'motor_renewal','occurred_at':'2026-10-01T11:00:00+05:30',
               'event_id':'2','payload_json':json.dumps({'disposition_code':'unknown'})}]
        self.assertEqual(select_effective_disposition(rows,D),'renewed')

if __name__ == '__main__': unittest.main()
