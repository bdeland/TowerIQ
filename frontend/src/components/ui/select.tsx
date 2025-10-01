import { 
  Select as MuiSelect, 
  MenuItem as MuiMenuItem, 
  FormControl,
  InputLabel,
  SelectProps as MuiSelectProps
} from '@mui/material';
import { ReactNode, forwardRef } from 'react';

interface SelectProps extends Omit<MuiSelectProps, 'children'> {
  children: ReactNode;
}

export const Select = forwardRef<HTMLDivElement, SelectProps>(
  ({ children, ...props }, ref) => {
    return (
      <FormControl size="small" ref={ref}>
        <MuiSelect {...props}>
          {children}
        </MuiSelect>
      </FormControl>
    );
  }
);
Select.displayName = 'Select';

export const SelectContent = ({ children }: { children: ReactNode }) => {
  return <>{children}</>;
};

export const SelectItem = ({ children, value }: { children: ReactNode; value: string }) => {
  return <MuiMenuItem value={value}>{children}</MuiMenuItem>;
};

export const SelectTrigger = ({ children, ...props }: { children: ReactNode } & any) => {
  return <>{children}</>;
};

export const SelectValue = ({ placeholder }: { placeholder?: string }) => {
  return <>{placeholder}</>;
};
