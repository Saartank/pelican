import { TextField } from '@mui/material';
import React, { useMemo } from 'react';
import { DateTimePicker, LocalizationProvider } from '@mui/x-date-pickers';
import { AdapterLuxon } from '@mui/x-date-pickers/AdapterLuxon';
import FormControl from '@mui/material/FormControl';
import FormHelperText from '@mui/material/FormHelperText';
import { DateTime } from 'luxon';

import type { BaseCustomRegistrationFieldProps } from './index';

const EpochTimeField = ({
  onChange,
  displayed_name,
  name,
  required,
  description,
  value,
}: BaseCustomRegistrationFieldProps<number>) => {
  return (
    <FormControl fullWidth>
      <DateTimePicker
        label={displayed_name}
        slotProps={{
          textField: {
            name: name,
            required: required,
            size: 'small',
          },
        }}
        value={value ? DateTime.fromSeconds(value) : null}
        onChange={(newValue: DateTime | null) => {
          onChange(newValue ? newValue.toUTC().toSeconds() : null);
        }}
      />
      {description && <FormHelperText>{description}</FormHelperText>}
    </FormControl>
  );
};

export default EpochTimeField;
export { EpochTimeField };
