'use client'

import React from 'react';
import AppLayout from '@/components/AppLayout';
import PhishingDetection from '@/components/PhishingDetection';

export default function PhishingPage() {
  return (
    <AppLayout>
      <PhishingDetection />
    </AppLayout>
  );
}