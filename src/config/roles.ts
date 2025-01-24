const allRoles: { user: string[]; admin: string[] } = {
  admin: ['getUsers', 'manageUsers'],
  user: ['joinRoom'],
};

export const roles = Object.keys(allRoles);
export const roleRights = new Map(Object.entries(allRoles));
