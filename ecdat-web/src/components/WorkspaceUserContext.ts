import { createContext, useContext } from 'react';
export type WorkspaceUser = {id:string; username:string; role:string};
export const UserContext = createContext<WorkspaceUser | null>(null);
export const useWorkspaceUser = () => useContext(UserContext);
