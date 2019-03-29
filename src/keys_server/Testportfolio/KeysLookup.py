# -*- coding: utf-8 -*-

__all__ = [
  'Test_portfolioKeysLookup'
] 

# Python standard library imports
import io
import json
import logging
import math
import os

# Python non-standard library imports
import pandas as pd

# Oasis utils and other Oasis imports
import importlib; import oasislmf
from oasislmf.utils.data import get_dataframe 
from oasislmf.utils.log import oasis_log
from oasislmf.utils.metadata import OASIS_KEYS_STATUS
from oasislmf.model_preparation.lookup import OasisLookupFactory as olf, OasisLookup, OasisPerilLookup, OasisVulnerabilityLookup

# Model keys server imports
from oasislmf.utils import *

class TestPortfolioLookup(olf):

    @oasis_log()
    def process_locations(self, loc_df):
        """
        Process location rows - passed in as a pandas dataframe.
        """
        for col in ['locnumber', 'occupancycode']:
            loc_df[col] = loc_df[col].astype(int)

        for index, row in loc_df.iterrows():
            # determine areaperil id
            lat = row['latitude']
            lon = row['longitude']
            occupancycode = row['occupancycode']
            area_peril_id, ap_message = self.get_areaperilid(lat,lon)
            
            occupancycode = row['occupancycode']

            if area_peril_id and vuln_cat:
                message = ''
                status = OASIS_KEYS_STATUS['success']['id'] #KEYS_STATUS_SUCCESS
                message = ''
                peril = OASIS_PERILS['WSS']['id'] #PERIL_ID_FLOOD,
                t2 = (self.vuln_types['occupancycode'] == vuln_cat + '_str')
                vulnerability_id = self.vuln_types[t2]['vulnerability_id'].values[0]
                
                yield {
                    "id": int(row['locnumber']),
                    "peril_id": 'WSS',
                    "coverage_type": 1,
                    "area_peril_id": int(area_peril_id),
                    "vulnerability_id": int(vulnerability_id),
                    "message": message,
                    "status": status
                }
                t2 = (self.vuln_types['occ_type'] == vuln_cat + '_cont')
                vulnerability_id = self.vuln_types[t2]['vulnerability_id'].values[0]

                yield {
                    "id": int(row['loc_number']),
                    "peril_id": 'WSS',
                    "coverage_type": 3,
                    "area_peril_id": area_peril_id,
                    "vulnerability_id": vulnerability_id,
                    "message": message,
                    "status": status
                }

            else:
                if area_peril_id:
                    message = vuln_message
                if vuln_cat:
                    message = ap_message
                if not area_peril_id and not vuln_cat:
                    message = ('{}, {}'.format(ap_message, vuln_message))
                
                status = OASIS_KEYS_STATUS['fail']['id'] #KEYS_STATUS_SUCCESS
                peril = OASIS_PERILS['WSS']['id'] #PERIL_ID_FLOOD,

                yield {
                    "id": int(row['loc_number']),
                    "peril_id": 'WSS',
                    "coverage_type": 1,
                    "message": message,
                    "status": status
                }

                yield {
                    "id": int(row['loc_number']),
                    "peril_id": 'WSS',
                    "coverage_type": 3,
                    "message": message,
                    "status": status
                }
